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

/// A Credential Query object
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlCredentialQuery {
    /// REQUIRED. A string identifying the Credential in the response.
    /// The value MUST be unique within a DCQL query.
    /// Valid characters are alphanumeric, underscore, and hyphen.
    id: String,

    /// REQUIRED. A string that specifies the requested format for the Credential.
    format: ClaimFormatDesignation,

    /// OPTIONAL. An object defining additional properties for the Credential.
    /// The properties are format-specific (e.g., `vct_values` for SD-JWT VC,
    /// `doctype_value` for mso_mdoc).
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<serde_json::Map<String, Json>>,

    /// OPTIONAL. An array of objects that specifies claims in the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<NonEmptyVec<DcqlCredentialClaimsQuery>>,

    /// OPTIONAL. An array of claim set identifiers for alternative claim combinations.
    /// MUST NOT be present if `claims` is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_sets: Option<NonEmptyVec<Vec<String>>>,

    /// OPTIONAL. An array of objects that specify expected trust frameworks.
    /// Each entry specifies a trust framework type and acceptable values.
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_authorities: Option<NonEmptyVec<TrustedAuthoritiesQuery>>,

    /// OPTIONAL. Boolean indicating if the Verifier requires cryptographic
    /// holder binding proof. Defaults to `true` if not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    require_cryptographic_holder_binding: Option<bool>,

    /// OPTIONAL. Boolean indicating if the Wallet may return multiple Credentials
    /// matching this query. Defaults to `false` if not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    multiple: Option<bool>,
}

impl DcqlCredentialQuery {
    pub fn new(id: String, format: ClaimFormatDesignation) -> Self {
        Self {
            id,
            format,
            meta: None,
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
            multiple: None,
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

    pub fn trusted_authorities(&self) -> Option<&NonEmptyVec<TrustedAuthoritiesQuery>> {
        self.trusted_authorities.as_ref()
    }

    pub fn trusted_authorities_mut(&mut self) -> &mut Option<NonEmptyVec<TrustedAuthoritiesQuery>> {
        &mut self.trusted_authorities
    }

    pub fn set_trusted_authorities(
        &mut self,
        trusted_authorities: Option<NonEmptyVec<TrustedAuthoritiesQuery>>,
    ) {
        self.trusted_authorities = trusted_authorities;
    }

    /// Returns `true` if cryptographic holder binding is required.
    /// Defaults to `true` per Section 6.1 if not explicitly set.
    pub fn require_cryptographic_holder_binding(&self) -> bool {
        self.require_cryptographic_holder_binding.unwrap_or(true)
    }

    pub fn require_cryptographic_holder_binding_raw(&self) -> Option<bool> {
        self.require_cryptographic_holder_binding
    }

    pub fn set_require_cryptographic_holder_binding(
        &mut self,
        require_cryptographic_holder_binding: Option<bool>,
    ) {
        self.require_cryptographic_holder_binding = require_cryptographic_holder_binding;
    }

    /// Returns `true` if multiple Credentials may be returned for this query.
    /// Defaults to `false` per Section 6.1 if not explicitly set.
    pub fn multiple(&self) -> bool {
        self.multiple.unwrap_or(false)
    }

    pub fn multiple_raw(&self) -> Option<bool> {
        self.multiple
    }

    pub fn set_multiple(&mut self, multiple: Option<bool>) {
        self.multiple = multiple;
    }
}

/// A Trusted Authorities Query object
/// Specifies expected trust frameworks for credential issuers.
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedAuthoritiesQuery {
    /// REQUIRED. A string uniquely identifying the type of trust framework.
    /// Defined types: "aki" (Authority Key Identifier), "etsi_tl" (ETSI Trusted List),
    /// "openid_federation" (OpenID Federation Entity Identifier).
    #[serde(rename = "type")]
    authority_type: TrustedAuthorityType,

    /// REQUIRED. A non-empty array of strings containing trust framework-specific
    /// identification data.
    values: NonEmptyVec<String>,
}

impl TrustedAuthoritiesQuery {
    pub fn new(authority_type: TrustedAuthorityType, values: NonEmptyVec<String>) -> Self {
        Self {
            authority_type,
            values,
        }
    }

    pub fn authority_type(&self) -> &TrustedAuthorityType {
        &self.authority_type
    }

    pub fn set_authority_type(&mut self, authority_type: TrustedAuthorityType) {
        self.authority_type = authority_type;
    }

    pub fn values(&self) -> &NonEmptyVec<String> {
        &self.values
    }

    pub fn values_mut(&mut self) -> &mut NonEmptyVec<String> {
        &mut self.values
    }

    pub fn set_values(&mut self, values: NonEmptyVec<String>) {
        self.values = values;
    }
}

/// Trusted Authority types
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedAuthorityType {
    /// Authority Key Identifier: the KeyIdentifier from an X.509 AuthorityKeyIdentifier,
    /// encoded as base64url.
    Aki,
    /// ETSI Trusted List: identifier per ETSI TS 119 612.
    EtsiTl,
    /// OpenID Federation Entity Identifier representing a Trust Anchor.
    OpenidFederation,
    /// Other trust framework type not defined in the spec.
    #[serde(untagged)]
    Other(String),
}

/// A Credential Set Query object 
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2
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
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
                multiple: None,
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

    #[test]
    fn dcql_credential_query_defaults() {
        // Test that defaults work
        let cred = DcqlCredentialQuery::new("test".into(), ClaimFormatDesignation::MsoMDoc);

        // require_cryptographic_holder_binding defaults to true
        assert!(cred.require_cryptographic_holder_binding());
        assert_eq!(cred.require_cryptographic_holder_binding_raw(), None);

        // multiple defaults to false
        assert!(!cred.multiple());
        assert_eq!(cred.multiple_raw(), None);
    }

    #[test]
    fn dcql_with_trusted_authorities() {
        let json = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://example.com/pid"]
                },
                "trusted_authorities": [
                    {
                        "type": "aki",
                        "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]
                    },
                    {
                        "type": "openid_federation",
                        "values": ["https://trustanchor.example.com"]
                    }
                ],
                "require_cryptographic_holder_binding": false,
                "multiple": true
            }]
        });

        let dcql: DcqlQuery = serde_json::from_value(json.clone()).unwrap();
        let cred = &dcql.credentials()[0];

        // Check trusted_authorities
        let authorities = cred.trusted_authorities().unwrap();
        assert_eq!(authorities.len(), 2);
        assert_eq!(
            authorities[0].authority_type(),
            &TrustedAuthorityType::Aki
        );
        assert_eq!(
            authorities[1].authority_type(),
            &TrustedAuthorityType::OpenidFederation
        );

        // Check explicit values override defaults
        assert!(!cred.require_cryptographic_holder_binding());
        assert!(cred.multiple());

        // Verify round-trip
        assert_eq!(json, serde_json::to_value(&dcql).unwrap());
    }
}
