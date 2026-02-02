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
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1>
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlCredentialQuery {
    /// REQUIRED. A string identifying the Credential in the response.
    /// The value MUST be unique within a DCQL query.
    /// Valid characters are alphanumeric, underscore, and hyphen.
    id: String,

    /// REQUIRED. A string that specifies the requested format for the Credential.
    format: ClaimFormatDesignation,

    /// REQUIRED. An object defining additional properties requested by the Verifier
    /// that apply to the metadata and validity data of the Credential.
    /// The properties are format-specific (e.g., `vct_values` for SD-JWT VC,
    /// `doctype_value` for mso_mdoc). If empty, no specific constraints are placed.
    /// Per OID4VP v1.0 §6.1, this field is REQUIRED but can be an empty object.
    #[serde(default)]
    meta: serde_json::Map<String, Json>,

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
            meta: serde_json::Map::new(),
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

    pub fn meta(&self) -> &serde_json::Map<String, Json> {
        &self.meta
    }

    pub fn meta_mut(&mut self) -> &mut serde_json::Map<String, Json> {
        &mut self.meta
    }

    pub fn set_meta(&mut self, meta: serde_json::Map<String, Json>) {
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
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1>
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
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1>
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
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2>
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlCredentialSetQuery {
    /// REQUIRED. A non-empty array where each value is a list of Credential Query
    /// identifiers representing one set of Credentials that satisfies the use case.
    options: NonEmptyVec<Vec<String>>,
    /// OPTIONAL. Boolean indicating whether this set of Credentials is required.
    /// Defaults to `true` per OID4VP v1.0 §6.2 if not explicitly set.
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<bool>,
}

impl DcqlCredentialSetQuery {
    pub fn new(options: NonEmptyVec<Vec<String>>) -> Self {
        Self {
            options,
            required: None,
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

    /// Returns `true` if this credential set is required.
    /// Defaults to `true` per OID4VP v1.0 §6.2 if not explicitly set.
    pub fn is_required(&self) -> bool {
        self.required.unwrap_or(true)
    }

    /// Returns the raw `required` value without applying the default.
    pub fn required_raw(&self) -> Option<bool> {
        self.required
    }

    pub fn required_mut(&mut self) -> &mut Option<bool> {
        &mut self.required
    }

    pub fn set_required(&mut self, required: Option<bool>) {
        self.required = required;
    }
}

/// A Claims Query object
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3>
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DcqlCredentialClaimsQuery {
    /// REQUIRED if `claim_sets` is present in the Credential Query; OPTIONAL otherwise.
    /// A string identifying the particular claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    /// REQUIRED. A non-empty array representing a claims path pointer that specifies
    /// the path to a claim within the Credential.
    path: NonEmptyVec<DcqlCredentialClaimsQueryPath>,
    /// OPTIONAL. A non-empty array of strings, integers or boolean values that specifies
    /// the expected values of the claim. Per OID4VP v1.0 §6.3, this must be non-empty if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<NonEmptyVec<DcqlCredentialClaimsQueryValue>>,
    /// OPTIONAL (ISO mdoc specific per §B.2.4). Boolean equivalent to `IntentToRetain`
    /// variable defined in Section 8.3.2.1.2.1 of ISO.18013-5.
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

    pub fn values(&self) -> Option<&NonEmptyVec<DcqlCredentialClaimsQueryValue>> {
        self.values.as_ref()
    }

    pub fn values_mut(&mut self) -> &mut Option<NonEmptyVec<DcqlCredentialClaimsQueryValue>> {
        &mut self.values
    }

    pub fn set_values(&mut self, values: Option<NonEmptyVec<DcqlCredentialClaimsQueryValue>>) {
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

    /// Extracts the namespace from the path (for mso_mdoc credentials).
    ///
    /// For mdoc credentials, the DCQL path structure is `[namespace, element_identifier]`.
    /// This method returns the first String element of the path if present.
    /// See: [OID4VP §B.3.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.1)
    pub fn namespace(&self) -> Option<&str> {
        match self.path.first() {
            Some(DcqlCredentialClaimsQueryPath::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Extracts the element identifier from the path (for mso_mdoc credentials).
    ///
    /// For mdoc credentials, the DCQL path structure is `[namespace, element_identifier]`.
    /// This method returns the second String element of the path if present.
    /// See: [OID4VP §B.3.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.1)
    pub fn element_identifier(&self) -> Option<&str> {
        match self.path.get(1) {
            Some(DcqlCredentialClaimsQueryPath::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Extracts the claim name from the path.
    ///
    /// This returns the last String element in the path, which represents the
    /// actual claim/attribute name for most credential formats.
    ///
    /// For nested claims (e.g., `["address", "street"]`), this returns `"street"`.
    /// For mdoc claims (e.g., `["org.iso.18013.5.1", "given_name"]`), this returns `"given_name"`.
    pub fn claim_name(&self) -> Option<&str> {
        self.path.iter().rev().find_map(|element| {
            if let DcqlCredentialClaimsQueryPath::String(s) = element {
                Some(s.as_str())
            } else {
                None
            }
        })
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
              "options": [["0"]]
            }
          ]
        });
        let dcql_query_object = DcqlQuery {
            credentials: NonEmptyVec::new(DcqlCredentialQuery {
                id: "0".into(),
                format: ClaimFormatDesignation::MsoMDoc,
                meta: [(
                    "doctype_value".to_string(),
                    serde_json::Value::String("org.iso.18013.5.1.mDL".to_string()),
                )]
                .into_iter()
                .collect(),
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

        // meta defaults to empty map
        assert!(cred.meta().is_empty());
    }

    #[test]
    fn dcql_credential_set_query_defaults() {
        // Test that is_required() defaults to true per §6.2
        let cred_set = DcqlCredentialSetQuery::new(NonEmptyVec::new(vec!["cred1".into()]));

        assert!(cred_set.is_required());
        assert_eq!(cred_set.required_raw(), None);

        // Test explicit false
        let json = json!({
            "options": [["cred1"]],
            "required": false
        });
        let cred_set: DcqlCredentialSetQuery = serde_json::from_value(json).unwrap();
        assert!(!cred_set.is_required());
        assert_eq!(cred_set.required_raw(), Some(false));
    }

    #[test]
    fn dcql_deserialize_with_empty_meta() {
        // Per §6.1, meta is REQUIRED but can be empty
        let json = json!({
            "credentials": [{
                "id": "test",
                "format": "mso_mdoc",
                "meta": {}
            }]
        });

        let dcql: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(dcql.credentials()[0].meta().is_empty());
    }

    #[test]
    fn dcql_deserialize_without_meta_uses_default() {
        // If meta is missing, it should default to empty map
        let json = json!({
            "credentials": [{
                "id": "test",
                "format": "mso_mdoc"
            }]
        });

        let dcql: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(dcql.credentials()[0].meta().is_empty());
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
        assert_eq!(authorities[0].authority_type(), &TrustedAuthorityType::Aki);
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

    #[test]
    fn dcql_claims_path_extraction_mdoc() {
        // Test mdoc-style path: [namespace, element_identifier]
        let claim = DcqlCredentialClaimsQuery::new(
            vec![
                DcqlCredentialClaimsQueryPath::String("org.iso.18013.5.1".into()),
                DcqlCredentialClaimsQueryPath::String("given_name".into()),
            ]
            .try_into()
            .unwrap(),
        );

        assert_eq!(claim.namespace(), Some("org.iso.18013.5.1"));
        assert_eq!(claim.element_identifier(), Some("given_name"));
        assert_eq!(claim.claim_name(), Some("given_name"));
    }

    #[test]
    fn dcql_claims_path_extraction_nested() {
        // Test nested claim path: ["address", "street"]
        let claim = DcqlCredentialClaimsQuery::new(
            vec![
                DcqlCredentialClaimsQueryPath::String("address".into()),
                DcqlCredentialClaimsQueryPath::String("street".into()),
            ]
            .try_into()
            .unwrap(),
        );

        assert_eq!(claim.namespace(), Some("address"));
        assert_eq!(claim.element_identifier(), Some("street"));
        assert_eq!(claim.claim_name(), Some("street"));
    }

    #[test]
    fn dcql_claims_path_extraction_with_array_index() {
        // Test path with array index: ["items", 0, "name"]
        let claim = DcqlCredentialClaimsQuery::new(
            vec![
                DcqlCredentialClaimsQueryPath::String("items".into()),
                DcqlCredentialClaimsQueryPath::Integer(0),
                DcqlCredentialClaimsQueryPath::String("name".into()),
            ]
            .try_into()
            .unwrap(),
        );

        // namespace() only returns first String element
        assert_eq!(claim.namespace(), Some("items"));
        // element_identifier() returns None because path[1] is Integer
        assert_eq!(claim.element_identifier(), None);
        // claim_name() returns the last String element
        assert_eq!(claim.claim_name(), Some("name"));
    }

    #[test]
    fn dcql_claims_path_extraction_single_element() {
        // Test single element path: ["name"]
        let claim = DcqlCredentialClaimsQuery::new(
            vec![DcqlCredentialClaimsQueryPath::String("name".into())]
                .try_into()
                .unwrap(),
        );

        assert_eq!(claim.namespace(), Some("name"));
        assert_eq!(claim.element_identifier(), None);
        assert_eq!(claim.claim_name(), Some("name"));
    }
}
