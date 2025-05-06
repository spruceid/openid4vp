use std::{fmt, ops::Deref};

use crate::core::{
    metadata::parameters::verifier::{
        AuthorizationEncryptedResponseAlg, AuthorizationEncryptedResponseEnc,
        AuthorizationSignedResponseAlg, JWKs, VpFormats,
    },
    object::{ParsingErrorContext, TypedParameter, UntypedObject},
    presentation_definition::PresentationDefinition as PresentationDefinitionParsed,
    util::{base_request, AsyncHttpClient},
};
use anyhow::{anyhow, bail, Context, Error, Ok};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use url::Url;

use super::AuthorizationRequestObject;

#[derive(Debug, Clone)]
pub struct ClientId(pub String);

impl ClientId {
    /// Retrieves the `client_id_scheme` from the authorization request object.
    ///
    /// If the `client_id_scheme` is not present, it will be inferred from the `client_id`.
    pub fn resolve_scheme(&self, value: &UntypedObject) -> Result<Option<ClientIdScheme>, Error> {
        let client_id_scheme = value.get::<ClientIdScheme>();
        if client_id_scheme.is_some() {
            return client_id_scheme.transpose();
        }

        Ok(self
            .0
            .split(':')
            .next()
            .map(|s| ClientIdScheme(s.to_string())))
    }
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

#[derive(Debug, Clone, PartialEq)]
pub struct ClientIdScheme(pub String);

impl TypedParameter for ClientIdScheme {
    const KEY: &'static str = "client_id_scheme";
}

impl TryFrom<Json> for ClientIdScheme {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(ClientIdScheme(serde_json::from_value(value)?))
    }
}

impl From<ClientIdScheme> for Json {
    fn from(value: ClientIdScheme) -> Self {
        Json::String(value.0)
    }
}

impl ClientIdScheme {
    pub const DID: &str = "did";
    /// Deprecated, use `https` instead.
    pub const ENTITY_ID: &str = "entity_id";
    pub const HTTPS: &str = "https";
    pub const PREREGISTERED: &str = "pre-registered";
    pub const REDIRECT_URI: &str = "redirect_uri";
    pub const VERIFIER_ATTESTATION: &str = "verifier_attestation";
    pub const WEB_ORIGIN: &str = "web-origin";
    pub const X509_SAN_DNS: &str = "x509_san_dns";
    pub const X509_SAN_URI: &str = "x509_san_uri";
}

impl Deref for ClientIdScheme {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// `client_metadata` field in the Authorization Request.
///
/// client_metadata: OPTIONAL. A JSON object containing the Verifier metadata values.
/// It MUST be UTF-8 encoded. The following metadata parameters MAY be used:
///
/// jwks: OPTIONAL. A JWKS as defined in [RFC7591]. It MAY contain one or more public keys, such as those used by the Wallet as an input to a key agreement that may be used for encryption of the Authorization Response (see Section 7.3), or where the Wallet will require the public key of the Verifier to generate the Verifiable Presentation. This allows the Verifier to pass ephemeral keys specific to this Authorization Request. Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests.
/// vp_formats: REQUIRED when not available to the Wallet via another mechanism. As defined in Section 10.1.
/// authorization_signed_response_alg: OPTIONAL. As defined in [JARM].
/// authorization_encrypted_response_alg: OPTIONAL. As defined in [JARM].
/// authorization_encrypted_response_enc: OPTIONAL. As defined in [JARM].
/// Authoritative data the Wallet is able to obtain about the Client from other sources,
/// for example those from an OpenID Federation Entity Statement, take precedence over the
/// values passed in client_metadata. Other metadata parameters MUST be ignored unless a
/// profile of this specification explicitly defines them as usable in the client_metadata parameter.
///
///
/// See reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.4
///
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

impl ClientMetadata {
    /// Resolves the client metadata from the Authorization Request Object.
    ///
    /// If the client metadata is not passed by reference or value if the Authorization Request Object,
    /// then this function will return an error.
    pub async fn resolve<H: AsyncHttpClient>(
        request: &AuthorizationRequestObject,
        http_client: &H,
    ) -> Result<Self, Error> {
        if let Some(metadata) = request.get() {
            return metadata;
        }

        if let Some(metadata_uri) = request.get::<ClientMetadataUri>() {
            let uri = metadata_uri.parsing_error()?.0;
            let request = base_request()
                .method("GET")
                .uri(uri.to_string())
                .body(vec![])
                .context("failed to build client metadata request")?;

            let response = http_client
                .execute(request)
                .await
                .context(format!("failed to make client metadata request at {uri}"))?;

            let status = response.status();

            if !status.is_success() {
                bail!("client metadata request was unsuccessful (status: {status})")
            }

            return serde_json::from_slice::<Json>(response.body())
                .context(format!(
                "failed to parse client metadata response as JSON from {uri} (status: {status})"
            ))?
                .try_into()
                .context("failed to parse client metadata from JSON");
        }

        tracing::warn!("the client metadata was not passed by reference or value");
        Ok(ClientMetadata(UntypedObject::default()))
    }

    /// OPTIONAL. A JWKS as defined in
    /// [RFC7591](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#RFC7591).
    ///
    /// It MAY contain one or more public keys, such as those used by the Wallet as an input to a
    /// key agreement that may be used for encryption of the Authorization Response
    /// (see [Section 7.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#jarm)),
    /// or where the Wallet will require the public key of the Verifier to generate the Verifiable Presentation.
    ///
    /// This allows the Verifier to pass ephemeral keys specific to this Authorization Request.
    /// Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests.
    ///
    ///
    /// See reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.1
    ///
    /// The jwks_uri or jwks metadata parameters can be used by clients to register their public encryption keys.
    ///
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-4
    ///
    pub fn jwks(&self) -> Option<Result<JWKs, Error>> {
        self.0.get()
    }

    /// Return the `VpFormats` from the `client_metadata` field.
    ///
    /// vp_formats: REQUIRED when not available to the Wallet via another mechanism.
    ///
    /// As defined in [Section 10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#client_metadata_parameters).
    ///
    /// See reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.2
    pub fn vp_formats(&self) -> Result<VpFormats, Error> {
        self.0.get().ok_or(anyhow!("missing vp_formats"))?
    }

    /// OPTIONAL. As defined in [JARM](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#JARM).
    ///
    /// JARM -> JWT Secured Authorization Response Mode for OAuth 2.0
    ///
    /// The JWS [RFC7515](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7515)
    /// `alg` algorithm REQUIRED for signing authorization responses.
    ///
    /// If this is specified, the response will be signed using JWS and the configured algorithm.
    ///
    /// If unspecified, the default algorithm to use for signing authorization responses is RS256.
    ///
    /// The algorithm none is not allowed.
    ///
    ///  A list of defined ["alg" values](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1)
    /// for this use can be found in the IANA "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA](https://www.rfc-editor.org/rfc/rfc7515.html#ref-JWA); the initial contents of this registry are the values
    /// defined in Section 3.1 of [JWA](https://www.rfc-editor.org/rfc/rfc7515.html#ref-JWA).
    ///
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.3
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-3.2.1
    /// See: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
    ///
    pub fn authorization_signed_response_alg(
        &self,
    ) -> Result<AuthorizationSignedResponseAlg, Error> {
        self.0.get().unwrap_or(Ok(AuthorizationSignedResponseAlg(
            ssi::crypto::Algorithm::Rs256,
        )))
    }

    /// OPTIONAL. As defined in [JARM](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#JARM).
    ///
    /// JARM -> JWT Secured Authorization Response Mode for OAuth 2.0
    ///
    /// The JWE [RFC7516](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7516)
    /// `alg` algorithm REQUIRED for encrypting authorization responses.
    ///
    /// If both signing and encryption are requested, the response will be signed then encrypted,
    /// with the result being a Nested JWT, as defined in JWT
    /// [RFC7519](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7519).
    ///
    /// The default, if omitted, is that no encryption is performed.
    ///
    ///
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.4
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-3.4.1
    ///
    pub fn authorization_encrypted_response_alg(
        &self,
    ) -> Option<Result<AuthorizationEncryptedResponseAlg, Error>> {
        self.0.get()
    }

    /// OPTIONAL. As defined in [JARM](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#JARM).
    ///
    /// JARM -> JWT Secured Authorization Response Mode for OAuth 2.0
    ///
    /// The JWE [RFC7516](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7516) `enc` algorithm
    /// REQUIRED for encrypting authorization responses.
    ///
    /// If `authorization_encrypted_response_alg` is specified, the default for this value is `A128CBC-HS256`.
    ///
    /// When `authorization_encrypted_response_enc` is included, authorization_encrypted_response_alg MUST also be provided.
    ///
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.5
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-3.6.1
    ///
    pub fn authorization_encrypted_response_enc(
        &self,
    ) -> Option<Result<AuthorizationEncryptedResponseEnc, Error>> {
        match self.0.get() {
            Some(enc) => Some(enc),
            None => self
                .authorization_encrypted_response_alg()
                .map(|_| Ok(AuthorizationEncryptedResponseEnc("A128CBC-HS256".into()))),
        }
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
pub struct Nonce(String);

impl From<String> for Nonce {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Nonce {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Deref for Nonce {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Nonce {
    /// Crate a new `Nonce` with a random value of the given length.
    pub fn random(rng: &mut impl rand::Rng, length: usize) -> Self {
        use rand::distributions::{Alphanumeric, DistString};

        Self(Alphanumeric.sample_string(rng, length))
    }
}

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
const DC_API: &str = "dc_api";
const DC_API_JWT: &str = "dc_api.jwt";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(into = "String", from = "String")]
pub enum ResponseMode {
    /// The `direct_post` response mode as defined in OID4VP.
    DirectPost,
    /// The `direct_post.jwt` response mode as defined in OID4VP.
    DirectPostJwt,
    /// The `dc_api` response mode as defined in OID4VP.
    DcApi,
    /// The `dc_api.jwt` response mode as defined in OID4VP.
    DcApiJwt,
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
            DC_API => ResponseMode::DcApi,
            DC_API_JWT => ResponseMode::DcApiJwt,
            _ => ResponseMode::Unsupported(s),
        }
    }
}

impl From<ResponseMode> for String {
    fn from(s: ResponseMode) -> Self {
        match s {
            ResponseMode::DirectPost => DIRECT_POST.into(),
            ResponseMode::DirectPostJwt => DIRECT_POST_JWT.into(),
            ResponseMode::DcApi => DC_API.into(),
            ResponseMode::DcApiJwt => DC_API_JWT.into(),
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
            ResponseMode::DcApi => DC_API,
            ResponseMode::DcApiJwt => DC_API_JWT,
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

impl ResponseMode {
    pub fn is_jarm(&self) -> Result<bool, Error> {
        match self {
            ResponseMode::DirectPost => Ok(false),
            ResponseMode::DirectPostJwt => Ok(true),
            ResponseMode::DcApi => Ok(false),
            ResponseMode::DcApiJwt => Ok(true),
            ResponseMode::Unsupported(rm) => bail!("unsupported response_mode: {rm}"),
        }
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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
pub struct PresentationDefinition {
    raw: Json,
    parsed: PresentationDefinitionParsed,
}

impl PresentationDefinition {
    pub fn into_parsed(self) -> PresentationDefinitionParsed {
        self.parsed
    }

    pub fn parsed(&self) -> &PresentationDefinitionParsed {
        &self.parsed
    }
}

impl TryFrom<PresentationDefinitionParsed> for PresentationDefinition {
    type Error = Error;

    fn try_from(parsed: PresentationDefinitionParsed) -> Result<Self, Self::Error> {
        let raw = serde_json::to_value(parsed.clone())?;
        Ok(Self { raw, parsed })
    }
}

impl TypedParameter for PresentationDefinition {
    const KEY: &'static str = "presentation_definition";
}

impl TryFrom<Json> for PresentationDefinition {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let parsed = serde_json::from_value(value.clone())?;
        Ok(Self { raw: value, parsed })
    }
}

impl From<PresentationDefinition> for Json {
    fn from(value: PresentationDefinition) -> Self {
        value.raw
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

impl PresentationDefinitionUri {
    pub async fn resolve<H: AsyncHttpClient>(
        &self,
        http_client: &H,
    ) -> Result<PresentationDefinition, Error> {
        let url = self.0.to_string();

        let request = base_request()
            .method("GET")
            .uri(&url)
            .body(vec![])
            .context("failed to build presentation definition request")?;

        let response = http_client.execute(request).await.context(format!(
            "failed to make presentation definition request at {url}"
        ))?;

        let status = response.status();

        if !status.is_success() {
            bail!("presentation definition request was unsuccessful (status: {status})")
        }

        serde_json::from_slice::<Json>(response.body())
            .context(format!(
            "failed to parse presentation definition response as JSON from {url} (status: {status})"
        ))?
            .try_into()
            .context("failed to parse presentation definition from JSON")
    }
}

#[derive(Debug, Clone)]
pub struct ExpectedOrigins(pub Vec<String>);

impl TypedParameter for ExpectedOrigins {
    const KEY: &'static str = "expected_origins";
}

impl TryFrom<Json> for ExpectedOrigins {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(Self)?)
    }
}

impl From<ExpectedOrigins> for Json {
    fn from(value: ExpectedOrigins) -> Self {
        json!(value.0)
    }
}
