use std::fmt;

use crate::core::object::{TypedParameter, UntypedObject};
use anyhow::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use url::Url;

const DID: &str = "did";
const ENTITY_ID: &str = "entity_id";
const PREREGISTERED: &str = "pre-registered";
const REDIRECT_URI: &str = "redirect_uri";
const X509_SAN_DNS: &str = "x509_san_dns";
const X509_SAN_URI: &str = "x509_san_uri";

#[derive(Debug, Clone)]
pub struct ClientId(pub String);

#[derive(Debug, Clone, PartialEq)]
pub enum ClientIdScheme {
    Did,
    EntityId,
    PreRegistered,
    RedirectUri,
    X509SanDns,
    X509SanUri,
    Other(String),
}

impl TypedParameter for ClientId {
    const KEY: &'static str = "client_id";
}

impl TryFrom<Json> for ClientId {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<ClientId> for Json {
    fn from(value: ClientId) -> Self {
        Json::String(value.0)
    }
}

impl TypedParameter for ClientIdScheme {
    const KEY: &'static str = "client_id_scheme";
}

impl From<String> for ClientIdScheme {
    fn from(s: String) -> Self {
        match s.as_str() {
            DID => ClientIdScheme::Did,
            ENTITY_ID => ClientIdScheme::EntityId,
            PREREGISTERED => ClientIdScheme::PreRegistered,
            REDIRECT_URI => ClientIdScheme::RedirectUri,
            X509_SAN_DNS => ClientIdScheme::X509SanDns,
            X509_SAN_URI => ClientIdScheme::X509SanUri,
            _ => ClientIdScheme::Other(s),
        }
    }
}

impl From<ClientIdScheme> for String {
    fn from(cis: ClientIdScheme) -> Self {
        match cis {
            ClientIdScheme::Did => DID.into(),
            ClientIdScheme::EntityId => ENTITY_ID.into(),
            ClientIdScheme::PreRegistered => PREREGISTERED.into(),
            ClientIdScheme::RedirectUri => REDIRECT_URI.into(),
            ClientIdScheme::X509SanDns => X509_SAN_DNS.into(),
            ClientIdScheme::X509SanUri => X509_SAN_URI.into(),
            ClientIdScheme::Other(u) => u,
        }
    }
}

impl TryFrom<Json> for ClientIdScheme {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
            .map(String::into)
            .map_err(Error::from)
    }
}

impl From<ClientIdScheme> for Json {
    fn from(value: ClientIdScheme) -> Self {
        Json::String(value.into())
    }
}

impl fmt::Display for ClientIdScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientIdScheme::Did => DID,
            ClientIdScheme::EntityId => ENTITY_ID,
            ClientIdScheme::PreRegistered => PREREGISTERED,
            ClientIdScheme::RedirectUri => REDIRECT_URI,
            ClientIdScheme::X509SanDns => X509_SAN_DNS,
            ClientIdScheme::X509SanUri => X509_SAN_URI,
            ClientIdScheme::Other(o) => o,
        }
        .fmt(f)
    }
}

/// `client_metadata` field in the Authorization Request.
#[derive(Debug, Clone)]
pub struct ClientMetadata(pub UntypedObject);

impl TypedParameter for ClientMetadata {
    const KEY: &'static str = "client_metadata";
}

impl From<ClientMetadata> for Json {
    fn from(cm: ClientMetadata) -> Self {
        cm.0 .0.into()
    }
}

impl TryFrom<Json> for ClientMetadata {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(ClientMetadata)?)
    }
}

/// `client_metadata_uri` field in the Authorization Request.
#[derive(Debug, Clone)]
pub struct ClientMetadataUri(pub Url);

impl TypedParameter for ClientMetadataUri {
    const KEY: &'static str = "client_metadata_uri";
}

impl From<ClientMetadataUri> for Json {
    fn from(cmu: ClientMetadataUri) -> Self {
        cmu.0.to_string().into()
    }
}

impl TryFrom<Json> for ClientMetadataUri {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(ClientMetadataUri)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nonce(pub String);

impl TypedParameter for Nonce {
    const KEY: &'static str = "nonce";
}

impl TryFrom<Json> for Nonce {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<Nonce> for Json {
    fn from(value: Nonce) -> Self {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct Audience(pub String);

impl TypedParameter for Audience {
    const KEY: &'static str = "aud";
}

impl TryFrom<Json> for Audience {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<Audience> for Json {
    fn from(value: Audience) -> Json {
        Json::String(value.0)
    }
}

/// `redirect_uri` field in the Authorization Request.
#[derive(Debug, Clone)]
pub struct RedirectUri(pub Url);

impl TypedParameter for RedirectUri {
    const KEY: &'static str = "redirect_uri";
}

impl From<RedirectUri> for Json {
    fn from(cmu: RedirectUri) -> Self {
        cmu.0.to_string().into()
    }
}

impl TryFrom<Json> for RedirectUri {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(RedirectUri)?)
    }
}

/// `response_uri` field in the Authorization Request.
#[derive(Debug, Clone)]
pub struct ResponseUri(pub Url);

impl TypedParameter for ResponseUri {
    const KEY: &'static str = "response_uri";
}

impl From<ResponseUri> for Json {
    fn from(cmu: ResponseUri) -> Self {
        cmu.0.to_string().into()
    }
}

impl TryFrom<Json> for ResponseUri {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(ResponseUri)?)
    }
}

const DIRECT_POST: &str = "direct_post";
const DIRECT_POST_JWT: &str = "direct_post.jwt";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "String", from = "String")]
pub enum ResponseMode {
    /// The `direct_post` response mode as defined in OID4VP.
    DirectPost,
    /// The `direct_post.jwt` response mode as defined in OID4VP.
    DirectPostJwt,
    /// A ResponseMode that is unsupported by this library.
    Unsupported(String),
}

impl TypedParameter for ResponseMode {
    const KEY: &'static str = "response_mode";
}

impl From<String> for ResponseMode {
    fn from(s: String) -> Self {
        match s.as_str() {
            DIRECT_POST => ResponseMode::DirectPost,
            DIRECT_POST_JWT => ResponseMode::DirectPostJwt,
            _ => ResponseMode::Unsupported(s),
        }
    }
}

impl From<ResponseMode> for String {
    fn from(s: ResponseMode) -> Self {
        match s {
            ResponseMode::DirectPost => DIRECT_POST.into(),
            ResponseMode::DirectPostJwt => DIRECT_POST_JWT.into(),
            ResponseMode::Unsupported(u) => u,
        }
    }
}

impl TryFrom<Json> for ResponseMode {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let s: String = serde_json::from_value(value)?;
        Ok(s.into())
    }
}

impl From<ResponseMode> for Json {
    fn from(rm: ResponseMode) -> Self {
        String::from(rm).into()
    }
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseMode::DirectPost => DIRECT_POST,
            ResponseMode::DirectPostJwt => DIRECT_POST_JWT,
            ResponseMode::Unsupported(u) => u,
        }
        .fmt(f)
    }
}

impl Default for ResponseMode {
    fn default() -> Self {
        Self::Unsupported("fragment".into())
    }
}

const VP_TOKEN: &str = "vp_token";
const VP_TOKEN_ID_TOKEN: &str = "vp_token id_token";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(into = "String", from = "String")]
pub enum ResponseType {
    VpToken,
    VpTokenIdToken,
    Unsupported(String),
}

impl From<ResponseType> for String {
    fn from(rt: ResponseType) -> Self {
        match rt {
            ResponseType::VpToken => VP_TOKEN.into(),
            ResponseType::VpTokenIdToken => VP_TOKEN_ID_TOKEN.into(),
            ResponseType::Unsupported(s) => s,
        }
    }
}

impl From<String> for ResponseType {
    fn from(s: String) -> Self {
        match s.as_str() {
            VP_TOKEN => ResponseType::VpToken,
            VP_TOKEN_ID_TOKEN => ResponseType::VpTokenIdToken,
            _ => ResponseType::Unsupported(s),
        }
    }
}

impl TypedParameter for ResponseType {
    const KEY: &'static str = "response_type";
}

impl TryFrom<Json> for ResponseType {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let s: String = serde_json::from_value(value)?;
        Ok(s.into())
    }
}

impl From<ResponseType> for Json {
    fn from(rt: ResponseType) -> Self {
        Json::String(rt.into())
    }
}

#[derive(Debug, Clone)]
pub struct State(pub String);

impl TypedParameter for State {
    const KEY: &'static str = "state";
}

impl TryFrom<Json> for State {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<State> for Json {
    fn from(value: State) -> Self {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct PresentationDefinition(pub Json);

impl TypedParameter for PresentationDefinition {
    const KEY: &'static str = "presentation_definition";
}

impl TryFrom<Json> for PresentationDefinition {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(value).map(Self)
    }
}

impl From<PresentationDefinition> for Json {
    fn from(value: PresentationDefinition) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct PresentationDefinitionUri(pub Url);

impl TypedParameter for PresentationDefinitionUri {
    const KEY: &'static str = "presentation_definition_uri";
}

impl TryFrom<Json> for PresentationDefinitionUri {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(Self)?)
    }
}

impl From<PresentationDefinitionUri> for Json {
    fn from(value: PresentationDefinitionUri) -> Self {
        value.0.to_string().into()
    }
}
