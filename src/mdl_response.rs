use crate::presentation_exchange::InputDescriptor;
use crate::presentation_exchange::PresentationSubmission;
use crate::utils::NonEmptyVec;
use crate::utils::Openid4vpError;
use isomdl;
pub use isomdl::definitions::device_request::ItemsRequest;
use isomdl::definitions::helpers::NonEmptyMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jarm {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmission,
}

fn match_path_to_mdl_field(
    paths: NonEmptyVec<String>,
    mdl_field_paths: Vec<String>,
    namespace_name: String,
) -> Option<String> {
    let mut matched_mdl_paths: Vec<Option<String>> = paths
        .iter()
        .map(|suggested_path| {
            let suggested_field_name = suggested_path.strip_prefix("$['org.iso.18013.5.1']")?;
            let suggested_field_name = suggested_field_name.replace(['[', ']', '\''], "");
            let mut matches: Vec<Option<String>> = mdl_field_paths
                .iter()
                .map(|known_path| {
                    let known_path_field_name =
                        known_path.strip_prefix(&format!("{}{}", &namespace_name, "."));
                    if let Some(path) = known_path_field_name {
                        if *path == suggested_field_name {
                            Some(path.to_owned())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();
            matches.retain(|item| item.is_some());
            //TODO: if constraints limit = required and there are no matched paths for a certain field, throw an Error, if not then ignore.
            if !matches.is_empty() {
                matches.first()?.to_owned()
            } else {
                None
            }
        })
        .collect();

    matched_mdl_paths.retain(|path| path.is_some());
    if !matched_mdl_paths.is_empty() {
        matched_mdl_paths.first()?.to_owned() // always return the first match as defined in Presentation Exchange
    } else {
        None
    }
}

fn mdl_field_paths() -> Vec<String> {
    vec![
        "org.iso.18013.5.1.family_name".to_string(),
        "org.iso.18013.5.1.given_name".to_string(),
        "org.iso.18013.5.1.birth_date".to_string(),
        "org.iso.18013.5.1.issue_date".to_string(),
        "org.iso.18013.5.1.expiry_date".to_string(),
        "org.iso.18013.5.1.issuing_country".to_string(),
        "org.iso.18013.5.1.issuing_authority".to_string(),
        "org.iso.18013.5.1.document_number".to_string(),
        "org.iso.18013.5.1.portrait".to_string(),
        "org.iso.18013.5.1.driving_privileges".to_string(),
        "org.iso.18013.5.1.un_distinguishing_sign".to_string(),
        "org.iso.18013.5.1.administrative_number".to_string(),
        "org.iso.18013.5.1.sex".to_string(),
        "org.iso.18013.5.1.height".to_string(),
        "org.iso.18013.5.1.weight".to_string(),
        "org.iso.18013.5.1.eye_colour".to_string(),
        "org.iso.18013.5.1.hair_colour".to_string(),
        "org.iso.18013.5.1.birth_place".to_string(),
        "org.iso.18013.5.1.resident_address".to_string(),
        "org.iso.18013.5.1.portrait_capture_date".to_string(),
        "org.iso.18013.5.1.age_in_years".to_string(),
        "org.iso.18013.5.1.age_birth_year".to_string(),
        "org.iso.18013.5.1.age_over_18".to_string(),
        "org.iso.18013.5.1.age_over_21".to_string(),
        "org.iso.18013.5.1.issuing_jurisdiction".to_string(),
        "org.iso.18013.5.1.nationality".to_string(),
        "org.iso.18013.5.1.resident_city".to_string(),
        "org.iso.18013.5.1.resident_state".to_string(),
        "org.iso.18013.5.1.resident_postal_code".to_string(),
        "org.iso.18013.5.1.resident_country".to_string(),
        "org.iso.18013.5.1.aamva.domestic_driving_privileges".to_string(),
        "org.iso.18013.5.1.aamva.name_suffix".to_string(),
        "org.iso.18013.5.1.aamva.organ_donor".to_string(),
        "org.iso.18013.5.1.aamva.veteran".to_string(),
        "org.iso.18013.5.1.aamva.family_name_truncation".to_string(),
        "org.iso.18013.5.1.aamva.given_name_truncation".to_string(),
        "org.iso.18013.5.1.aamva.aka_family_name.v2".to_string(),
        "org.iso.18013.5.1.aamva.aka_given_name.v2".to_string(),
        "org.iso.18013.5.1.aamva.weight_range".to_string(),
        "org.iso.18013.5.1.aamva.race_ethnicity".to_string(),
        "org.iso.18013.5.1.aamva.EDL_credential".to_string(),
        "org.iso.18013.5.1.aamva.DHS_compliance".to_string(),
        "org.iso.18013.5.1.aamva.sex".to_string(),
        "org.iso.18013.5.1.aamva.resident_county".to_string(),
        "org.iso.18013.5.1.aamva.hazmat_endorsement_expiration_date".to_string(),
        "org.iso.18013.5.1.aamva.CDL_indicator".to_string(),
        "org.iso.18013.5.1.aamva.DHS_compliance_text".to_string(),
        "org.iso.18013.5.1.aamva.DHS_temporary_lawful_status".to_string(),
    ]
}

impl TryFrom<InputDescriptor> for ItemsRequest {
    type Error = Openid4vpError;
    fn try_from(input_descriptor: InputDescriptor) -> Result<Self, Openid4vpError> {
        if let Some(constraints) = input_descriptor.constraints {
            let doc_type = "org.iso.18013.5.1.mDL".to_string();
            let namespace_name = "org.iso.18013.5.1".to_string();
            let constraints_fields = constraints.fields;

            if let Some(cf) = constraints_fields {
                let mut fields: BTreeMap<Option<String>, Option<bool>> = cf
                    .iter()
                    .map(|constraints_field| {
                        let path = match_path_to_mdl_field(
                            constraints_field.path.clone(),
                            mdl_field_paths(),
                            namespace_name.clone(),
                        );
                        if let Some(p) = path {
                            (Some(p), constraints_field.intent_to_retain)
                        } else {
                            (None, None)
                        }
                    })
                    .collect();

                fields.retain(|k, _v| k.is_some());
                let x: BTreeMap<Option<String>, Option<bool>> = fields
                    .iter()
                    .map(|(k, v)| {
                        if v.is_none() {
                            (k.to_owned(), Some(false))
                        } else {
                            (k.to_owned(), v.to_owned())
                        }
                    })
                    .collect();
                // safe unwraps
                let requested_fields: BTreeMap<String, bool> = x
                    .iter()
                    .map(|(k, v)| (k.clone().unwrap(), v.unwrap()))
                    .collect();

                let namespace: NonEmptyMap<String, bool> = NonEmptyMap::try_from(requested_fields)?;
                let namespaces = NonEmptyMap::new(namespace_name, namespace);

                Ok(ItemsRequest {
                    namespaces,
                    doc_type,
                    request_info: None,
                })
            } else {
                Err(Openid4vpError::Empty)
            }
        } else {
            Err(Openid4vpError::Empty)
        }
    }
}
