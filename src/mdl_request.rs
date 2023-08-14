use crate::utils::Openid4vpError;
use crate::{
    presentation_exchange::{
        Constraints, ConstraintsField, InputDescriptor, PresentationDefinition,
    },
    utils::NonEmptyVec,
};
use isomdl::definitions::helpers::NonEmptyMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssi::jwk::JWK;
use std::collections::BTreeMap;
use x509_cert::der::referenced::OwnedToRef;
use x509_cert::der::Decode;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestObject {
    // Omitting iss is okay since the client_id is already in the request object
    // pub iss: String,
    pub aud: String,
    pub response_type: String,
    pub client_id: String,
    pub client_id_scheme: Option<String>,
    pub response_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(flatten)]
    pub presentation_definition: PresDef,
    #[serde(flatten)]
    pub client_metadata: MetaData,
    pub response_mode: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum MetaData {
    ClientMetadata { client_metadata: ClientMetadata },
    ClientMetadataUri { client_metadata_uri: String },
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum PresDef {
    PresentationDefinition {
        presentation_definition: PresentationDefinition,
    },
    PresentationDefintionUri {
        presentation_definition_uri: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClientMetadata {
    pub authorization_encrypted_response_alg: String,
    pub authorization_encrypted_response_enc: String,
    pub require_signed_request_object: bool,
    pub jwks: Value,
    pub vp_formats: Value,
}

pub fn prepare_mdl_request_object(
    jwk: JWK,
    requested_fields: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
    client_id: String,
    response_uri: String,
    presentation_id: String,
) -> Result<RequestObject, Openid4vpError> {
    let presentation_definition = mdl_presentation_definition(requested_fields, presentation_id)?;
    let client_metadata = ClientMetadata {
        authorization_encrypted_response_alg: "ES256".to_string(),
        authorization_encrypted_response_enc: "A128GCM".to_string(),
        vp_formats: json!({"mso_mdoc": {
            "alg": [
                "ES256"
            ]
        }}),
        jwks: json!(jwk),
        require_signed_request_object: false,
    };

    Ok(RequestObject {
        aud: "https://self-issued.me/v2".to_string(), // per openid4vp chapter 5.6
        response_type: "vp_token".to_string(),
        client_id: client_id.clone(),
        client_id_scheme: Some("x509_san_uri".to_string()),
        response_uri: Some(response_uri),
        scope: Some("openid".to_string()), // I think it could also be None
        state: None,
        presentation_definition: PresDef::PresentationDefinition {
            presentation_definition,
        },
        client_metadata: MetaData::ClientMetadata { client_metadata },
        response_mode: Some("direct_post.jwt".to_string()),
        nonce: Some(client_id), //TODO: should be some nonce
    })
}

fn mdl_presentation_definition(
    namespaces: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
    presentation_id: String,
) -> Result<PresentationDefinition, Openid4vpError> {
    let input_descriptors = build_input_descriptors(namespaces);
    Ok(PresentationDefinition {
        id: presentation_id,
        input_descriptors,
        name: None,
        purpose: None,
        format: None,
    })
}

//TODO: allow for specifying the algorithm
fn build_input_descriptors(
    namespaces: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
) -> Vec<InputDescriptor> {
    let path_base = "$['org.iso.18013.5.1']";

    // let doc_type_filter = json!({
    //     "type": "string",
    //     "const": "org.iso.18013.5.1.mDL"
    // });

    let input_descriptors: Vec<InputDescriptor> = namespaces
        .iter()
        .map(|namespace| {
            let format = json!({
            "mso_mdoc": {
                "alg": [
                    "ES256"
                    //TODO: add all supported algorithms
                ]
            }});
            let mut namespace_fields = BTreeMap::from(namespace.1.to_owned());
            namespace_fields.retain(|k, _v| k.is_some());

            let fields: Vec<ConstraintsField> = namespace_fields
                .iter()
                .map(|field| {
                    ConstraintsField {
                        //safe unwrap since none values are removed above
                        path: NonEmptyVec::new(format!(
                            "{}['{}']",
                            path_base,
                            field.0.as_ref().unwrap().to_owned()
                        )),
                        id: None,
                        purpose: None,
                        name: None,
                        filter: None,
                        optional: None,
                        intent_to_retain: *field.1,
                    }
                })
                .collect();

            let constraints = Constraints {
                fields: Some(fields),
                limit_disclosure: Some(
                    crate::presentation_exchange::ConstraintsLimitDisclosure::Required,
                ),
            };

            InputDescriptor {
                id: "org.iso.18013.5.1.mDL ".to_string(),
                name: None,
                purpose: None,
                format: Some(format),
                constraints: Some(constraints),
                schema: None,
            }
        })
        .collect();

    input_descriptors
}

pub fn x509_public_key(der: Vec<u8>) -> Result<p256::PublicKey, String> {
    x509_cert::Certificate::from_der(&der)
        .map_err(|e| format!("could not parse certificate from DER: {e}"))?
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref()
        .try_into()
        .map_err(|e| format!("could not parse p256 public key from pkcs8 spki: {e}"))
}

fn _minimal_mdl_request_isomdl() -> BTreeMap<String, bool> {
    BTreeMap::from([
        ("org.iso.18013.5.1.family_name".to_string(), false),
        ("org.iso.18013.5.1.given_name".to_string(), false),
        ("org.iso.18013.5.1.birth_date".to_string(), false),
        ("org.iso.18013.5.1.issue_date".to_string(), false),
        ("org.iso.18013.5.1.expiry_date".to_string(), false),
        ("org.iso.18013.5.1.issuing_country".to_string(), false),
        ("org.iso.18013.5.1.issuing_authority".to_string(), false),
        ("org.iso.18013.5.1.document_number".to_string(), false),
        ("org.iso.18013.5.1.portrait".to_string(), false),
        ("org.iso.18013.5.1.driving_privileges".to_string(), false),
        (
            "org.iso.18013.5.1.un_distinguishing_sign".to_string(),
            false,
        ),
        ("org.iso.18013.5.1.administrative_number".to_string(), false),
        ("org.iso.18013.5.1.sex".to_string(), false),
        ("org.iso.18013.5.1.height".to_string(), false),
        ("org.iso.18013.5.1.weight".to_string(), false),
        ("org.iso.18013.5.1.eye_colour".to_string(), false),
        ("org.iso.18013.5.1.hair_colour".to_string(), false),
        ("org.iso.18013.5.1.birth_place".to_string(), false),
        ("org.iso.18013.5.1.resident_address".to_string(), false),
        ("org.iso.18013.5.1.portrait_capture_date".to_string(), false),
        ("org.iso.18013.5.1.age_in_years".to_string(), false),
        ("org.iso.18013.5.1.age_birth_year".to_string(), false),
        ("org.iso.18013.5.1.age_over_18".to_string(), true),
        ("org.iso.18013.5.1.age_over_21".to_string(), true),
        ("org.iso.18013.5.1.issuing_jurisdiction".to_string(), false),
        ("org.iso.18013.5.1.nationality".to_string(), false),
        ("org.iso.18013.5.1.resident_city".to_string(), false),
        ("org.iso.18013.5.1.resident_state".to_string(), false),
        ("org.iso.18013.5.1.resident_postal_code".to_string(), false),
        ("org.iso.18013.5.1.resident_country".to_string(), false),
    ])
}

fn _aamva_isomdl_data() -> BTreeMap<String, bool> {
    BTreeMap::from([
        ("domestic_driving_privileges".to_string(), false),
        ("name_suffix".to_string(), false),
        ("organ_donor".to_string(), false),
        ("veteran".to_string(), false),
        ("family_name_truncation".to_string(), false),
        ("given_name_truncation".to_string(), false),
        ("aka_family_name.v2".to_string(), false),
        ("aka_given_name.v2".to_string(), false),
        ("weight_range".to_string(), false),
        ("race_ethnicity".to_string(), false),
        ("EDL_credential".to_string(), false),
        ("DHS_compliance".to_string(), false),
        ("sex".to_string(), false),
        ("resident_county".to_string(), false),
        ("hazmat_endorsement_expiration_date".to_string(), false),
        ("CDL_indicator".to_string(), false),
        ("DHS_compliance_text".to_string(), false),
        ("DHS_temporary_lawful_status".to_string(), false),
    ])
}

pub fn minimal_mdl_request() -> BTreeMap<Option<String>, Option<bool>> {
    BTreeMap::from([
        (
            Some("org.iso.18013.5.1.family_name".to_string()),
            Some(true),
        ),
        (Some("org.iso.18013.5.1.given_name".to_string()), Some(true)),
        (
            Some("org.iso.18013.5.1.birth_date".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.issue_date".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.expiry_date".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.issuing_country".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.issuing_authority".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.document_number".to_string()),
            Some(false),
        ),
        (Some("org.iso.18013.5.1.portrait".to_string()), Some(false)),
        (
            Some("org.iso.18013.5.1.driving_privileges".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.un_distinguishing_sign".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.administrative_number".to_string()),
            Some(false),
        ),
        (Some("org.iso.18013.5.1.sex".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.height".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.weight".to_string()), Some(false)),
        (
            Some("org.iso.18013.5.1.eye_colour".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.hair_colour".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.birth_place".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.resident_address".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.portrait_capture_date".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.age_in_years".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.age_birth_year".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.age_over_18".to_string()),
            Some(true),
        ),
        (
            Some("org.iso.18013.5.1.age_over_21".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.issuing_jurisdiction".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.nationality".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.resident_city".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.resident_state".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.resident_postal_code".to_string()),
            Some(false),
        ),
        (
            Some("org.iso.18013.5.1.resident_country".to_string()),
            Some(false),
        ),
    ])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn request_example() {
        const DID_JWK: &str = r#"{"kty":"EC","crv":"secp256k1","x":"nrVtymZmqiSu9lU8DmVnB6W7XayJUj4uN7hC3uujZ9s","y":"XZA56MU96ne2c2K-ldbZxrAmLOsneJL1lE4PFnkyQnA","d":"mojL_WMJuMp1vmHNLUkc4es6IeAfcDB7qyZqTeKCEqE"}"#;
        let minimal_mdl_request = NonEmptyMap::try_from(minimal_mdl_request()).unwrap();
        let namespaces = NonEmptyMap::new("org.iso.18013.5.1".to_string(), minimal_mdl_request);
        let client_id = "nonce".to_string();
        let redirect_uri = "localhost::3000".to_string();
        let presentation_id = "mDL".to_string();

        let jwk: JWK = serde_json::from_str(DID_JWK).unwrap();
        let _request_object =
            prepare_mdl_request_object(jwk, namespaces, client_id, redirect_uri, presentation_id)
                .unwrap();
    }
}