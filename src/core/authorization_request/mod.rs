use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, bail, Context, Error, Result};
use parameters::{ClientMetadata, PresentationDefinitionUri, State};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::wallet::Wallet;

use self::{
    parameters::{
        ClientId, ClientIdScheme, Nonce, PresentationDefinition, RedirectUri, ResponseMode,
        ResponseType, ResponseUri,
    },
    verification::verify_request,
};

use super::{
    metadata::parameters::verifier::VpFormats,
    object::{ParsingErrorContext, UntypedObject},
    util::{base_request, AsyncHttpClient},
};

pub mod parameters;
pub mod verification;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct AuthorizationRequestObject {
    inner: UntypedObject,
    client_id: ClientId,
    client_id_scheme: Option<ClientIdScheme>,
    response_mode: ResponseMode,
    response_type: ResponseType,
    return_uri: Url,
    nonce: Nonce,
}

/// An Authorization Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    #[serde(flatten)]
    pub request_indirection: RequestIndirection,
}

/// A RequestObject, passed by value or by reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestIndirection {
    #[serde(rename = "request")]
    ByValue(String),
    #[serde(rename = "request_uri")]
    ByReference(Url),
}

/// A PresentationDefinition, passed by value or by reference
#[derive(Debug, Clone)]
pub enum PresentationDefinitionIndirection {
    ByValue(PresentationDefinition),
    ByReference(Url),
}

impl AuthorizationRequest {
    /// Validate the [AuthorizationRequest] according to the client_id scheme and return the parsed
    /// [RequestObject].
    ///
    /// Custom wallet metadata can be provided, otherwise the default metadata for this profile is used.
    pub async fn validate<W: Wallet + ?Sized>(
        self,
        wallet: &W,
    ) -> Result<AuthorizationRequestObject> {
        let jwt = match self.request_indirection {
            RequestIndirection::ByValue(jwt) => jwt,
            RequestIndirection::ByReference(url) => {
                let request = base_request()
                    .method("GET")
                    .uri(url.to_string())
                    .body(vec![])
                    .context("failed to build authorization request request")?;

                let response = wallet
                    .http_client()
                    .execute(request)
                    .await
                    .context(format!(
                        "failed to make authorization request request at {url}"
                    ))?;

                let status = response.status();
                let Ok(body) = String::from_utf8(response.into_body()) else {
                    bail!("failed to parse authorization request response as UTF-8 from {url} (status: {status})")
                };

                if !status.is_success() {
                    bail!(
                        "authorization request request was unsuccessful (status: {status}): {body}"
                    )
                }

                body
            }
        };
        let aro = verify_request(wallet, jwt)
            .await
            .context("unable to validate Authorization Request")?;
        let aro_client_id_raw = aro.get::<ClientId>().parsing_error()?;
        if self.client_id.as_str() != aro_client_id_raw.0.as_str() {
            bail!(
                "Authorization Request and Request Object have different client ids: '{}' vs. '{}'",
                self.client_id,
                aro_client_id_raw.0
            );
        }
        Ok(aro)
    }

    /// Encode as [Url], using the `authorization_endpoint` as a base.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// # use url::Url;
    /// let authorization_endpoint: Url = "example://".parse().unwrap();
    /// let authorization_request = AuthorizationRequest {
    ///     client_id: "xyz".to_string(),
    ///     request_indirection: RequestIndirection::ByValue("test".to_string()),
    /// };
    ///
    /// let authorization_request_url = authorization_request.to_url(authorization_endpoint).unwrap();
    ///
    /// assert_eq!(authorization_request_url.as_str(), "example://?client_id=xyz&request=test");
    /// ```
    pub fn to_url(self, mut authorization_endpoint: Url) -> Result<Url> {
        let query = serde_urlencoded::to_string(self)?;
        authorization_endpoint.set_query(Some(&query));
        Ok(authorization_endpoint)
    }

    /// Parse from [Url], validating the authorization_endpoint.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// # use url::Url;
    /// let url: Url = "example://?client_id=xyz&request=test".parse().unwrap();
    /// let authorization_endpoint: Url = "example://".parse().unwrap();
    ///
    /// let authorization_request = AuthorizationRequest::from_url(
    ///     url,
    ///     &authorization_endpoint
    /// ).unwrap();
    ///
    /// assert_eq!(authorization_request.client_id, "xyz");
    ///
    /// let RequestIndirection::ByValue(request_object) =
    ///     authorization_request.request_indirection
    /// else {
    ///     panic!("expected request-by-value")
    /// };
    ///
    /// assert_eq!(request_object, "test");
    /// ```
    pub fn from_url(url: Url, authorization_endpoint: &Url) -> Result<Self> {
        let query = url
            .query()
            .ok_or(anyhow!("missing query params in Authorization Request uri"))?
            .to_string();
        let fnd = url.authority();
        let exp = authorization_endpoint.authority();
        if fnd != exp {
            bail!("unexpected authorization_endpoint authority, expected '{exp}', received '{fnd}'")
        }
        let fnd = url.path();
        let exp = authorization_endpoint.path();
        if fnd != exp {
            bail!("unexpected authorization_endpoint path, expected '{exp}', received '{fnd}'")
        }
        Self::from_query_params(&query)
    }

    /// Parse from urlencoded query parameters.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// let query = "client_id=xyz&request=test";
    ///
    /// let authorization_request = AuthorizationRequest::from_query_params(query).unwrap();
    ///
    /// assert_eq!(authorization_request.client_id, "xyz");
    ///
    /// let RequestIndirection::ByValue(request_object) = authorization_request.request_indirection
    /// else { panic!("expected request-by-value") };
    /// assert_eq!(request_object, "test");
    /// ```
    pub fn from_query_params(query_params: &str) -> Result<Self> {
        serde_urlencoded::from_str(query_params)
            .context("unable to parse Authorization Request from query params")
    }
}

impl AuthorizationRequestObject {
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn client_id_scheme(&self) -> Option<&ClientIdScheme> {
        self.client_id_scheme.as_ref()
    }

    pub async fn resolve_presentation_definition<H: AsyncHttpClient>(
        &self,
        http_client: &H,
    ) -> Result<Option<PresentationDefinition>> {
        let pd = self.get::<PresentationDefinition>().transpose()?;

        let pd_uri = self.get::<PresentationDefinitionUri>().transpose()?;

        match (pd, pd_uri) {
            (Some(presentation_definition), None) => Ok(Some(presentation_definition)),
            (None, Some(presentation_definition_uri)) => Ok(Some(
                presentation_definition_uri
                    .resolve(http_client)
                    .await
                    .unwrap(),
            )),
            (Some(_), Some(_)) => {
                bail!("only one of presentation_definition or presentation_definition_uri should be provided");
            }
            (None, None) => Ok(None),
        }
    }

    pub fn is_id_token_requested(&self) -> Option<bool> {
        match self.response_type {
            ResponseType::VpToken => Some(false),
            ResponseType::VpTokenIdToken => Some(true),
            ResponseType::Unsupported(_) => None,
        }
    }

    pub fn response_mode(&self) -> &ResponseMode {
        &self.response_mode
    }

    pub fn response_type(&self) -> &ResponseType {
        &self.response_type
    }

    /// Uri to submit the response at.
    ///
    /// AKA [ResponseUri] or [RedirectUri] depending on [ResponseMode].
    pub fn return_uri(&self) -> &Url {
        &self.return_uri
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Return the `client_metadata` field from the authorization request.
    pub fn client_metadata(&self) -> Result<ClientMetadata> {
        self.get()
            .ok_or(anyhow!("missing `client_metadata` object"))?
    }

    /// Return the `VpFormats` from the `client_metadata` field.
    pub fn vp_formats(&self) -> Result<VpFormats> {
        self.client_metadata()?
            .0
            .get()
            .ok_or(anyhow!("missing vp_formats"))?
    }

    /// Return the `state` of the authorization request,
    /// if it was provided.
    pub fn state(&self) -> Option<Result<State>> {
        self.get()
    }
}

impl From<AuthorizationRequestObject> for UntypedObject {
    fn from(value: AuthorizationRequestObject) -> Self {
        value.inner
    }
}

impl TryFrom<UntypedObject> for AuthorizationRequestObject {
    type Error = Error;

    fn try_from(value: UntypedObject) -> std::result::Result<Self, Self::Error> {
        let client_id = value.get::<ClientId>().parsing_error()?;
        let client_id_scheme = client_id.resolve_scheme(&value)?;

        let redirect_uri = value.get::<RedirectUri>();
        let response_uri = value.get::<ResponseUri>();

        let (return_uri, response_mode) = match (
            redirect_uri,
            response_uri,
            value.get_or_default::<ResponseMode>().parsing_error()?,
        ) {
            (_, _, ResponseMode::Unsupported(m)) => {
                bail!("this 'response_mode' ({m}) is not currently supported")
            }
            (Some(_), Some(_), _) => {
                bail!("'response_uri' and 'redirect_uri' are mutually exclusive")
            }
            (_, None, response_mode @ ResponseMode::DirectPost)
            | (_, None, response_mode @ ResponseMode::DirectPostJwt) => {
                bail!("'response_uri' is required for this 'response_mode' ({response_mode})")
            }
            (_, Some(uri), response_mode @ ResponseMode::DirectPost)
            | (_, Some(uri), response_mode @ ResponseMode::DirectPostJwt) => {
                (uri.parsing_error()?.0, response_mode)
            }
            (_, Some(_), response_mode @ ResponseMode::DcApi)
            | (_, Some(_), response_mode @ ResponseMode::DcApiJwt) => {
                bail!("'response_uri' cannot be present for this 'response_mode' ({response_mode})")
            }
            (Some(_), _, response_mode @ ResponseMode::DcApi)
            | (Some(_), _, response_mode @ ResponseMode::DcApiJwt) => {
                bail!("'redirect_uri' cannot be present for this 'response_mode' ({response_mode})")
            }
            (None, None, response_mode @ ResponseMode::DcApi)
            | (None, None, response_mode @ ResponseMode::DcApiJwt) => {
                ("https://example.com".parse()?, response_mode)
            }
        };

        let response_type: ResponseType = value.get().parsing_error()?;

        let nonce = value.get().parsing_error()?;

        Ok(Self {
            inner: value,
            client_id,
            client_id_scheme,
            response_mode,
            response_type,
            return_uri,
            nonce,
        })
    }
}

impl Deref for AuthorizationRequestObject {
    type Target = UntypedObject;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for AuthorizationRequestObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
