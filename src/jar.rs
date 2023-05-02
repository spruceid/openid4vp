use std::vec;

use crate::{
    presentation_exchange::{
        Constraints, ConstraintsField, ConstraintsLimitDisclosure, InputDescriptor,
        PresentationDefinition,
    },
    utils::NonEmptyVec,
};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use siop::openidconnect::Nonce;
use ssi::{self, jwk::JWK};
use uuid::Uuid;

pub enum RequestType {
    BY_REFERENCE,
    BY_VALUE,
}

fn gen_nonce() -> Nonce {
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    Nonce::new(nonce)
}

pub fn get_request_object(
    signing_key: ssi::jwk::JWK,
    id: Uuid,
) -> Result<String, ssi::jws::error::Error> {
    let constraint = ConstraintsField {
        path: NonEmptyVec::new("path".to_string()),
        id: None,
        purpose: None,
        name: None,
        filter: None,
        optional: None,
        intent_to_retain: Some(false),
    };

    let format = json!({
        "mso_mdoc": {
            "alg": ["EdDSA","ES256"]
        }
    });

    let input_descriptor = InputDescriptor {
        id: "mDL".to_string(),
        name: Some("name".to_string()),
        purpose: Some("purpose".to_string()),
        format: Some(format),
        constraints: Some(Constraints {
            fields: Some(vec![constraint]),
            limit_disclosure: None,
        }),
        schema: None,
    };

    let presentation_definition = PresentationDefinition {
        id: "mDL".to_string(),
        input_descriptors: vec![input_descriptor],
        name: None,
        purpose: None,
        format: None,
    };

    let auth_request_jwt = RequestObject {
        iss: "456".to_string(),
        aud: "some value".to_string(),
        response_type: "code".to_string(),
        client_id: id.to_string(),
        client_id_scheme: Some("wib".to_string()),
        redirect_uri: Some("xyz".to_string()),
        scope: Some("asd".to_string()),
        state: "someopauquestring".to_string(),
        presentation_definition: Some(presentation_definition),
        presentation_definition_uri: Some("x".to_string()),
        client_metadata: "String".to_string(),
        client_metadata_uri: Some(serde_json::Value::String("".to_string())),
        response_mode: Some("direct_post".to_string()),
    };
    let algorithm = signing_key.algorithm.unwrap();
    ssi::jwt::encode_sign(algorithm, &auth_request_jwt, &signing_key)
}

pub fn get_jar_by_reference(
    api_prefix: String,
    id: Uuid,
    jwk: JWK,
) -> Result<String, ssi::jws::Error> {
    let jar = JwtAuthorizationRequest {
        request: None,
        request_uri: Some(format!("{}/{}/request", api_prefix, id)),
        nonce: gen_nonce(),
        response_type: "vp_token".to_string(),
        client_id: id.to_string(),
    };

    ssi::jwt::encode_sign(jwk.get_algorithm().unwrap(), &jar, &jwk)
}

pub fn get_jar_by_value(id: Uuid, jwk: JWK) -> Result<String, ssi::jws::Error> {
    let ar = get_request_object(jwk.clone(), id)?;

    let jar = JwtAuthorizationRequest {
        request: Some(ar),
        request_uri: None,
        nonce: gen_nonce(),
        response_type: "vp_token".to_string(),
        client_id: id.to_string(),
    };

    ssi::jwt::encode_sign(jwk.get_algorithm().unwrap(), &jar, &jwk)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtAuthorizationRequest {
    pub request: Option<String>,
    pub request_uri: Option<String>,
    pub nonce: Nonce,
    pub response_type: String,
    pub client_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestObject {
    pub iss: String,
    pub aud: String,
    pub response_type: String,
    pub client_id: String,
    pub client_id_scheme: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: String,
    pub presentation_definition: Option<PresentationDefinition>,
    pub presentation_definition_uri: Option<String>,
    pub client_metadata: String,
    pub client_metadata_uri: Option<Value>,
    pub response_mode: Option<String>,
}

pub struct AuthorizationResponse {
    code: String,
    state: String,
}
