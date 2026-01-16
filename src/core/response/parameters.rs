pub use crate::core::authorization_request::parameters::State;
use crate::core::object::TypedParameter;

use anyhow::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use ssi::{
    claims::vc::{self, v2::SpecializedJsonCredential},
    json_ld::syntax::Object,
    prelude::{AnyDataIntegrity, AnyJsonPresentation, AnySuite, DataIntegrity},
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct IdToken(pub String);

impl TypedParameter for IdToken {
    const KEY: &'static str = "id_token";
}

impl TryFrom<Json> for IdToken {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map(Self).map_err(Into::into)
    }
}

impl From<IdToken> for Json {
    fn from(value: IdToken) -> Self {
        value.0.into()
    }
}

/// The `vp_token` parameter for Authorization Response.
///
/// When using DCQL, the `vp_token` is a JSON object where:
/// - Keys are the credential query `id` values from the DCQL query
/// - Values are arrays of Verifiable Presentations matching that query
///
/// From [OID4VP Section 6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1):
/// > `vp_token`: REQUIRED when the Response Type value is `vp_token`. JSON object with
/// > keys matching the `id` values from the Credential Queries in the `dcql_query` and
/// > values being arrays of Verifiable Presentations.
///
/// Each presentation in the array can be:
/// - A JSON string (e.g., SD-JWT VC, JWT VP)
/// - A JSON object (e.g., JSON-LD VP with Data Integrity proof)
///
/// Example:
/// ```json
/// {
///   "my_credential": ["eyJhbGci..."],
///   "other_credential": [{"@context": [...], ...}]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VpToken(pub HashMap<String, Vec<VpTokenItem>>);

impl VpToken {
    /// Create a new empty VpToken.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Create a VpToken with a single credential query result.
    pub fn with_credential(credential_id: impl Into<String>, presentations: Vec<VpTokenItem>) -> Self {
        let mut map = HashMap::new();
        map.insert(credential_id.into(), presentations);
        Self(map)
    }

    /// Add presentations for a credential query.
    pub fn insert(&mut self, credential_id: impl Into<String>, presentations: Vec<VpTokenItem>) {
        self.0.insert(credential_id.into(), presentations);
    }

    /// Get presentations for a credential query ID.
    pub fn get(&self, credential_id: &str) -> Option<&Vec<VpTokenItem>> {
        self.0.get(credential_id)
    }

    /// Check if the token is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the number of credential queries answered.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over all credential query IDs and their presentations.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<VpTokenItem>)> {
        self.0.iter()
    }
}

impl Default for VpToken {
    fn default() -> Self {
        Self::new()
    }
}

impl TypedParameter for VpToken {
    const KEY: &'static str = "vp_token";
}

impl TryFrom<Json> for VpToken {
    type Error = anyhow::Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(Into::into)
    }
}

impl From<VpToken> for Json {
    fn from(value: VpToken) -> Self {
        serde_json::to_value(value)
            // SAFETY: a vp token has a valid JSON representation by definition.
            .unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VpTokenItem {
    String(String),
    JsonObject(serde_json::Map<String, serde_json::Value>),
}

impl From<String> for VpTokenItem {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<AnyDataIntegrity> for VpTokenItem {
    fn from(value: AnyDataIntegrity) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(&value)
            // SAFETY: by definition a Data Integrity Object is a Json LD Node and is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a Data Integrity Object is a Json LD Node and is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<vc::v1::syntax::JsonPresentation> for VpTokenItem {
    fn from(value: vc::v1::syntax::JsonPresentation) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<vc::v2::syntax::JsonPresentation> for VpTokenItem {
    fn from(value: vc::v2::syntax::JsonPresentation) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>> for VpTokenItem {
    fn from(value: vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<AnyJsonPresentation> for VpTokenItem {
    fn from(value: AnyJsonPresentation) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<DataIntegrity<AnyJsonPresentation, AnySuite>> for VpTokenItem {
    fn from(value: DataIntegrity<AnyJsonPresentation, AnySuite>) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}
