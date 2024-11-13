pub use crate::core::authorization_request::parameters::State;
use crate::core::object::TypedParameter;

use anyhow::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use ssi::{
    claims::vc::{self, v2::SpecializedJsonCredential},
    json_ld::syntax::Object,
    one_or_many::OneOrManyRef,
    prelude::{AnyDataIntegrity, AnyJsonPresentation},
    OneOrMany,
};

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

/// OpenID Connect for Verifiable Presentations specification defines `vp_token` parameter:
///
/// > JSON String or JSON object that MUST contain a single Verifiable Presentation or
/// > an array of JSON Strings and JSON objects each of them containing a Verifiable Presentations.
/// >
/// > Each Verifiable Presentation MUST be represented as a JSON string (that is a Base64url encoded value)
/// > or a JSON object depending on a format as defined in Appendix A of [OpenID.VCI].
/// >
/// > If Appendix A of [OpenID.VCI] defines a rule for encoding the respective Credential
/// > format in the Credential Response, this rules MUST also be followed when encoding Credentials of
/// > this format in the vp_token response parameter. Otherwise, this specification does not require
/// > any additional encoding when a Credential format is already represented as a JSON object or a JSON string.
///
/// See: [OpenID.VP#section-6.1-2.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.2)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VpToken(pub Vec<VpTokenItem>);

impl VpToken {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<VpTokenItem> {
        self.0.iter()
    }
}

impl TypedParameter for VpToken {
    const KEY: &'static str = "vp_token";
}

impl Serialize for VpToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OneOrManyRef::from_slice(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VpToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        OneOrMany::<VpTokenItem>::deserialize(deserializer)
            .map(OneOrMany::into_vec)
            .map(Self)
    }
}

impl From<VpTokenItem> for VpToken {
    fn from(value: VpTokenItem) -> Self {
        Self(vec![value])
    }
}

impl From<String> for VpToken {
    fn from(value: String) -> Self {
        Self(vec![value.into()])
    }
}

impl From<vc::v1::syntax::JsonPresentation> for VpToken {
    fn from(value: vc::v1::syntax::JsonPresentation) -> Self {
        Self(vec![value.into()])
    }
}

impl From<vc::v2::syntax::JsonPresentation> for VpToken {
    fn from(value: vc::v2::syntax::JsonPresentation) -> Self {
        Self(vec![value.into()])
    }
}

impl From<vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>> for VpToken {
    fn from(value: vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>) -> Self {
        Self(vec![value.into()])
    }
}

impl From<AnyJsonPresentation> for VpToken {
    fn from(value: AnyJsonPresentation) -> Self {
        Self(vec![value.into()])
    }
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

impl<'a> IntoIterator for &'a VpToken {
    type IntoIter = std::slice::Iter<'a, VpTokenItem>;
    type Item = &'a VpTokenItem;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for VpToken {
    type IntoIter = std::vec::IntoIter<VpTokenItem>;
    type Item = VpTokenItem;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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
