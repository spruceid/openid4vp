use crate::utils::Error;
use crate::{
    presentation_exchange::{
        Constraints, ConstraintsField, InputDescriptor,
        PresentationDefinition,
    },
    utils::NonEmptyVec,
};
use serde_json::{json, Value};
use isomdl::definitions::helpers::NonEmptyMap;
use ssi::jwk::JWK;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use x509_cert::der::Decode;
use x509_cert::der::referenced::OwnedToRef;

use crate::{
    mdl_request::{self},
};

#[derive(Clone, Debug, Serialize, Deserialize,)]
pub struct RequestObject {
    // pub iss: String, omitting iss is okay since the client_id is already in the request object
    pub aud: String,
    pub response_type: String,
    pub client_id: String,
    pub client_id_scheme: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: String,
    pub presentation_definition: Option<PresentationDefinition>,
    pub presentation_definition_uri: Option<String>,
    pub client_metadata: mdl_request::ClientMetadata,
    pub client_metadata_uri: Option<Value>,
    pub response_mode: Option<String>,
    pub nonce: Option<String>,
    pub supported_algorithm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize,)]
pub struct ClientMetadata {
    pub authorization_encrypted_response_alg: String,
    pub authorization_encrypted_response_enc: String,
    pub jwks: Value,
    pub vp_formats: String,
    pub client_id_scheme: Option<String>,
}

pub fn prepare_mdl_request_object(jwk: JWK, requested_fields: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>> , client_id: String, redirect_uri: String, presentation_id: String) -> Result<RequestObject, Error>{
    let presentation_definition = mdl_presentation_definition(requested_fields, presentation_id)?;
    let client_metadata = ClientMetadata {
        authorization_encrypted_response_alg: "ES256".to_string(),
        authorization_encrypted_response_enc: "A128GCM".to_string(),
        vp_formats: "mso_mdoc".to_string(), // TODO fix
        client_id_scheme: Some("ISO_X509".to_string()),
        jwks: json!(jwk),
    };

    Ok( RequestObject{
        aud: "https://self-issued.me/v2".to_string(),  // per openid4vp chapter 5.6
        response_type: "vp_token".to_string(),
        client_id: client_id.clone(),
        client_id_scheme: Some("ISO_X509".to_string()),
        redirect_uri: Some(redirect_uri),
        scope: Some("openid".to_string()), // I think it could also be None
        state:"".to_string(), 
        presentation_definition: Some(presentation_definition),
        presentation_definition_uri: None,
        client_metadata,
        client_metadata_uri: None,
        response_mode: Some("direct_post.jwt".to_string()),
        nonce: Some(client_id),
        supported_algorithm: "ES256".to_string()
    })
}

fn mdl_presentation_definition(
    namespaces: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>>,
    presentation_id: String
) -> Result<PresentationDefinition, Error> {
    let input_descriptors = build_input_descriptors(namespaces);
    Ok(PresentationDefinition{
        id: presentation_id,
        input_descriptors: input_descriptors,
        name: None,
        purpose: None,
        format: None,
    })
}

//TODO: allow for specifying the algorithm
fn build_input_descriptors(namespaces: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>>) -> Vec<InputDescriptor>{
    let path_base = "$.mdoc.";

    let doc_type_filter = json!({
            "type": "string",
            "const": "org.iso.18013.5.1.mDL"
        });

    let input_descriptors: Vec<InputDescriptor> = namespaces.iter().map(|namespace| {
        let namespace_filter = json!({
            "type": "string",
            "const": namespace.0
        });

        let format = json!({
            "mso_mdoc": {
                "alg": [
                    "EdDSA",
                    "ES256"
                    //TODO add all supported algorithms
                ]
            }});
        let mut namespace_fields = BTreeMap::from(namespace.1.to_owned());
        namespace_fields.retain(|k, _v| k.is_some());

        let mut fields: Vec<ConstraintsField> =  namespace_fields.iter().map(|field| {
            ConstraintsField { 
                //safe unwrap since none values are removed above
                path: NonEmptyVec::new(format!("{}{}", path_base, field.0.as_ref().unwrap().to_owned())),
                id: None,
                purpose:None,
                name:None,
                filter: None,
                optional: None,
                intent_to_retain: *field.1 
            
            }
        }).collect();

        fields.push(ConstraintsField {
            path: NonEmptyVec::new(format!("{}{}", path_base, "doc_type")),
            id: None,
            purpose: None,
            name: None,
            filter: Some(doc_type_filter.clone()),
            optional: None,
            intent_to_retain: None,
        });
    
        fields.push(ConstraintsField {
            path: NonEmptyVec::new(format!("{}{}", path_base, "namespace")),
            id: None,
            purpose: None,
            name: None,
            filter: Some(namespace_filter),
            optional: None,
            intent_to_retain: None,
        });

        let constraints = Constraints{
            fields: Some(fields),
            limit_disclosure: None,
        };

        InputDescriptor{ 
            id: "mDL".to_string(),
            name: None,
            purpose: None,
            format: Some(format),
            constraints: Some(constraints),
            schema: None }
    }).collect();

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
        ("org.iso.18013.5.1.un_distinguishing_sign".to_string(), false),
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
        ("org.iso.18013.5.1.age_over_18".to_string(), true,),
        ("org.iso.18013.5.1.age_over_21".to_string(), true,),
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
        (Some("org.iso.18013.5.1.family_name".to_string()),Some( true)),
        (Some("org.iso.18013.5.1.given_name".to_string()),Some( true)),
        (Some("org.iso.18013.5.1.birth_date".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.issue_date".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.expiry_date".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.issuing_country".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.issuing_authority".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.document_number".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.portrait".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.driving_privileges".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.un_distinguishing_sign".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.administrative_number".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.sex".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.height".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.weight".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.eye_colour".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.hair_colour".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.birth_place".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.resident_address".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.portrait_capture_date".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.age_in_years".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.age_birth_year".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.age_over_18".to_string()), Some(true,)),
        (Some("org.iso.18013.5.1.age_over_21".to_string()), Some(false,)),
        (Some("org.iso.18013.5.1.issuing_jurisdiction".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.nationality".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.resident_city".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.resident_state".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.resident_postal_code".to_string()), Some(false)),
        (Some("org.iso.18013.5.1.resident_country".to_string()), Some(false)),
        
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
        let presentation_id = "test minimal mdl request".to_string();
        
        let jwk: JWK = serde_json::from_str(DID_JWK).unwrap();
        let request_object = prepare_mdl_request_object(jwk, namespaces, client_id, redirect_uri, presentation_id).unwrap();

        println!("request object: {:?}", request_object);

    }
}