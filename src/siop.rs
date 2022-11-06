use openidconnect::{
    core::{
        CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
    },
    AuthUrl, Nonce, RedirectUrl, ResponseTypes, Scope,
};
use serde::{Deserialize, Serialize};
use ssi::{did::DIDURL, jwk::JWK};

#[derive(Serialize, Deserialize)]
pub struct RequestParameters {
    scope: Scope,
    response_type: CoreResponseType,
    response_mode: CoreResponseMode,
    client_id: String, // DIDURL, // TODO should just be a DID but it's private in ssi
    redirect_uri: RedirectUrl,
    nonce: Nonce,
}

impl RequestParameters {
    pub fn new(client_id: String, redirect_uri: RedirectUrl, nonce: Nonce) -> Self {
        Self {
            scope: Scope::new("openid".to_string()),
            response_type: CoreResponseType::IdToken,
            response_mode: CoreResponseMode::Extension("post".to_string()),
            client_id,
            redirect_uri,
            nonce,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum IdTokenType {
    SubjectSigned,
}

// pub type CoreProviderMetadata = ProviderMetadata<EmptyAdditionalProviderMetadata, CoreAuthDisplay, CoreClientAuthMethod, CoreClaimName, CoreClaimType, CoreGrantType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType>;

#[derive(Deserialize, Serialize)]
struct StaticDiscoveryMetadata {
    authorization_endpoint: AuthUrl,
    response_types_supported: Vec<CoreResponseType>,
    scopes_supported: Vec<Scope>,
    subject_types_supported: Vec<CoreSubjectIdentifierType>,
    id_token_signing_alg_values_supported: Vec<CoreJwsSigningAlgorithm>,
    request_object_signing_alg_values_supported: Vec<CoreJwsSigningAlgorithm>,
    subject_syntax_types_supported: Vec<String>,
    id_token_types_supported: Vec<IdTokenType>,
}

impl StaticDiscoveryMetadata {
    fn new() -> Self {
        Self {
            authorization_endpoint: AuthUrl::new("openid:".to_string()).unwrap(),
            response_types_supported: vec![CoreResponseType::IdToken],
            scopes_supported: vec![Scope::new("openid".to_string())],
            subject_types_supported: vec![CoreSubjectIdentifierType::Pairwise],
            id_token_signing_alg_values_supported: vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256],
            request_object_signing_alg_values_supported: vec![
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            ],
            subject_syntax_types_supported: vec!["urn:ietf:params:oauth:jwk-thumbprint".to_string()],
            id_token_types_supported: vec![IdTokenType::SubjectSigned],
        }
    }
}

// lazy_static::lazy_static! {
//     static ref STATIC_DISCOVERY_METADATA: StaticDiscoveryMetadata = StaticDiscoveryMetadata {
//         authorization_endpoint: AuthUrl::new("openid:".to_string()).unwrap(),
//         response_types_supported: ResponseTypes::new(vec![CoreResponseType::IdToken]),
//         scopes_supported: vec![Scope::new("openid".to_string())],
//         subject_types_supported: vec![CoreSubjectIdentifierType::Pairwise],
//         id_token_signing_alg_values_supported: vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256],
//         request_object_signing_alg_values_supported: vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256],
//         subject_syntax_types_supported: vec!["urn:ietf:params:oauth:jwk-thumbprint".to_string()],
//         id_token_types_supported: vec![IdTokenType::SubjectSigned],
//     };
// }

#[derive(Deserialize)]
pub struct IdTokenSIOP {
    iss: String,
    sub: String,
    sub_jwk: Option<JWK>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn const_static_metadata() {
        let value = json!({
            "authorization_endpoint": "openid:",
            "response_types_supported": [
                "id_token"
            ],
            "scopes_supported": [
                "openid"
            ],
            "subject_types_supported": [
                "pairwise"
            ],
            "id_token_signing_alg_values_supported": [
                "ES256"
            ],
            "request_object_signing_alg_values_supported": [
                "ES256"
            ],
            "subject_syntax_types_supported": [
                "urn:ietf:params:oauth:jwk-thumbprint"
            ],
            "id_token_types_supported": [
                "subject_signed"
            ]
        });
        assert_eq!(
            serde_json::to_value(&StaticDiscoveryMetadata::new()).unwrap(),
            value
        );
    }
}
