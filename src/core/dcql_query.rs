use crate::{
    core::{credential_format::ClaimFormatDesignation, object::TypedParameter},
    utils::NonEmptyVec,
};
use anyhow::{Error, Ok};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlQuery {
    credentials: NonEmptyVec<DcqlCredentialQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_sets: Option<NonEmptyVec<DcqlCredentialSetQuery>>,
}

impl DcqlQuery {
    pub fn new(credentials: NonEmptyVec<DcqlCredentialQuery>) -> Self {
        Self {
            credentials,
            credential_sets: None,
        }
    }

    pub fn set_credential_sets(
        &mut self,
        credential_sets: Option<NonEmptyVec<DcqlCredentialSetQuery>>,
    ) {
        self.credential_sets = credential_sets;
    }

    pub fn credential_sets(&self) -> Option<&NonEmptyVec<DcqlCredentialSetQuery>> {
        self.credential_sets.as_ref()
    }

    pub fn credential_sets_mut(&mut self) -> &mut Option<NonEmptyVec<DcqlCredentialSetQuery>> {
        &mut self.credential_sets
    }

    pub fn credentials(&self) -> &[DcqlCredentialQuery] {
        &self.credentials
    }

    pub fn credentials_mut(&mut self) -> &mut NonEmptyVec<DcqlCredentialQuery> {
        &mut self.credentials
    }

    pub fn set_credentials(&mut self, credentials: NonEmptyVec<DcqlCredentialQuery>) {
        self.credentials = credentials;
    }
}

impl TypedParameter for DcqlQuery {
    const KEY: &'static str = "dcql_query";
}

impl TryFrom<Json> for DcqlQuery {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value)?)
    }
}

impl From<DcqlQuery> for Json {
    fn from(value: DcqlQuery) -> Self {
        serde_json::to_value(&value).unwrap() // TODO
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlCredentialQuery {
    id: String,
    format: ClaimFormatDesignation,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<serde_json::Map<String, Json>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<NonEmptyVec<DcqlCredentialClaimsQuery>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_sets: Option<NonEmptyVec<Vec<String>>>,
}

impl DcqlCredentialQuery {
    pub fn new(id: String, format: ClaimFormatDesignation) -> Self {
        Self {
            id,
            format,
            meta: None,
            claims: None,
            claim_sets: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn id_mut(&mut self) -> &mut String {
        &mut self.id
    }

    pub fn set_id(&mut self, id: String) {
        self.id = id;
    }

    pub fn format(&self) -> &ClaimFormatDesignation {
        &self.format
    }

    pub fn format_mut(&mut self) -> &mut ClaimFormatDesignation {
        &mut self.format
    }

    pub fn set_format(&mut self, format: ClaimFormatDesignation) {
        self.format = format;
    }

    pub fn meta(&self) -> Option<&serde_json::Map<String, Json>> {
        self.meta.as_ref()
    }

    pub fn meta_mut(&mut self) -> &mut Option<serde_json::Map<String, Json>> {
        &mut self.meta
    }

    pub fn set_meta(&mut self, meta: Option<serde_json::Map<String, Json>>) {
        self.meta = meta;
    }

    pub fn claims(&self) -> Option<&NonEmptyVec<DcqlCredentialClaimsQuery>> {
        self.claims.as_ref()
    }

    pub fn claims_mut(&mut self) -> &mut Option<NonEmptyVec<DcqlCredentialClaimsQuery>> {
        &mut self.claims
    }

    pub fn set_claims(&mut self, claims: Option<NonEmptyVec<DcqlCredentialClaimsQuery>>) {
        self.claims = claims;
    }

    pub fn claim_sets(&self) -> Option<&NonEmptyVec<Vec<String>>> {
        self.claim_sets.as_ref()
    }

    pub fn claim_sets_mut(&mut self) -> &mut Option<NonEmptyVec<Vec<String>>> {
        &mut self.claim_sets
    }

    pub fn set_claim_sets(&mut self, claim_sets: Option<NonEmptyVec<Vec<String>>>) {
        self.claim_sets = claim_sets;
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlCredentialSetQuery {
    options: NonEmptyVec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<Json>,
}

impl DcqlCredentialSetQuery {
    pub fn new(options: NonEmptyVec<Vec<String>>) -> Self {
        Self {
            options,
            required: None,
            purpose: None,
        }
    }

    pub fn options(&self) -> &NonEmptyVec<Vec<String>> {
        &self.options
    }

    pub fn options_mut(&mut self) -> &mut NonEmptyVec<Vec<String>> {
        &mut self.options
    }

    pub fn set_options(&mut self, options: NonEmptyVec<Vec<String>>) {
        self.options = options;
    }

    pub fn required(&self) -> Option<bool> {
        self.required
    }

    pub fn required_mut(&mut self) -> &mut Option<bool> {
        &mut self.required
    }

    pub fn set_required(&mut self, required: Option<bool>) {
        self.required = required;
    }

    pub fn purpose(&self) -> Option<&Json> {
        self.purpose.as_ref()
    }

    pub fn purpose_mut(&mut self) -> &mut Option<Json> {
        &mut self.purpose
    }

    pub fn set_purpose(&mut self, purpose: Option<Json>) {
        self.purpose = purpose;
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlCredentialClaimsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    path: NonEmptyVec<DcqlCredentialClaimsQueryPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<Vec<DcqlCredentialClaimsQueryValue>>,
    /// Only applicable for ClaimFormatDesignation::MsoMdoc
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_to_retain: Option<bool>,
}

impl DcqlCredentialClaimsQuery {
    pub fn new(path: NonEmptyVec<DcqlCredentialClaimsQueryPath>) -> Self {
        Self {
            id: None,
            path,
            values: None,
            intent_to_retain: None,
        }
    }

    pub fn id(&self) -> Option<&String> {
        self.id.as_ref()
    }

    pub fn id_mut(&mut self) -> &mut Option<String> {
        &mut self.id
    }

    pub fn set_id(&mut self, id: Option<String>) {
        self.id = id;
    }

    pub fn path(&self) -> &[DcqlCredentialClaimsQueryPath] {
        &self.path
    }

    pub fn path_mut(&mut self) -> &mut NonEmptyVec<DcqlCredentialClaimsQueryPath> {
        &mut self.path
    }

    pub fn set_path(&mut self, path: NonEmptyVec<DcqlCredentialClaimsQueryPath>) {
        self.path = path;
    }

    pub fn values(&self) -> Option<&Vec<DcqlCredentialClaimsQueryValue>> {
        self.values.as_ref()
    }

    pub fn values_mut(&mut self) -> &mut Option<Vec<DcqlCredentialClaimsQueryValue>> {
        &mut self.values
    }

    pub fn set_values(&mut self, values: Option<Vec<DcqlCredentialClaimsQueryValue>>) {
        self.values = values;
    }

    pub fn intent_to_retain(&self) -> Option<bool> {
        self.intent_to_retain
    }

    pub fn intent_to_retain_mut(&mut self) -> &mut Option<bool> {
        &mut self.intent_to_retain
    }

    pub fn set_intent_to_retain(&mut self, intent_to_retain: Option<bool>) {
        self.intent_to_retain = intent_to_retain;
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum DcqlCredentialClaimsQueryValue {
    String(String),
    Integer(isize),
    Boolean(bool),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum DcqlCredentialClaimsQueryPath {
    String(String),
    Null,
    Integer(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn de_serialize_dcql_query() {
        let dcql_query_json = json!({
          "credentials": [
            {
              "id": "0",
              "format": "mso_mdoc",
              "meta": {
                "doctype_value": "org.iso.18013.5.1.mDL"
              },
              "claims": [
                {
                  "path": [
                    "org.iso.18013.5.1",
                    "given_name"
                  ],
                  "intent_to_retain": false
                },
              ]
            }
          ],
          "credential_sets": [
            {
              "options": [["0"]],
              "purpose": "Authorize to the government using your mobile drivers license"
            }
          ]
        });
        let dcql_query_object = DcqlQuery {
            credentials: NonEmptyVec::new(DcqlCredentialQuery {
                id: "0".into(),
                format: ClaimFormatDesignation::MsoMDoc,
                meta: Some(
                    [(
                        "doctype_value".to_string(),
                        serde_json::Value::String("org.iso.18013.5.1.mDL".to_string()),
                    )]
                    .into_iter()
                    .collect(),
                ),
                claims: Some(NonEmptyVec::new(DcqlCredentialClaimsQuery {
                    id: None,
                    path: vec![
                        DcqlCredentialClaimsQueryPath::String("org.iso.18013.5.1".into()),
                        DcqlCredentialClaimsQueryPath::String("given_name".into()),
                    ]
                    .try_into()
                    .unwrap(),
                    values: None,
                    intent_to_retain: Some(false),
                })),
                claim_sets: None,
            }),
            credential_sets: Some(NonEmptyVec::new(DcqlCredentialSetQuery {
                options: NonEmptyVec::new(vec!["0".into()]),
                required: None,
                purpose: Some(serde_json::Value::String(
                    "Authorize to the government using your mobile drivers license".into(),
                )),
            })),
        };
        assert_eq!(
            dcql_query_json,
            serde_json::to_value(&dcql_query_object).unwrap()
        );
        assert_eq!(
            dcql_query_object,
            serde_json::from_value(dcql_query_json).unwrap()
        );
    }
}
