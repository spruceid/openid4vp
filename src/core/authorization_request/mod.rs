use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, bail, Context, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use url::Url;

use self::{
    parameters::{
        ClientId, ClientIdScheme, Nonce, PresentationDefinition, PresentationDefinitionUri,
        RedirectUri, ResponseMode, ResponseType, ResponseUri,
    },
    verification::verify_request,
};

use super::{
    object::{ParsingErrorContext, UntypedObject},
    profile::Wallet,
    util::default_http_client,
};

pub mod builder;
pub mod parameters;
pub mod verification;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct AuthorizationRequestObject(
    UntypedObject,
    ClientId,
    ClientIdScheme,
    ResponseMode,
    ResponseType,
    PresentationDefinitionIndirection,
    Url,
    Nonce,
);

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
    pub async fn validate_with_http_client<WP: Wallet + ?Sized>(
        self,
        wallet_profile: &WP,
        http_client: &reqwest::Client,
    ) -> Result<AuthorizationRequestObject> {
        let jwt = match self.request_indirection {
            RequestIndirection::ByValue(jwt) => jwt,
            RequestIndirection::ByReference(url) => http_client
                .get(url.clone())
                .send()
                .await
                .context(format!("failed to GET {url}"))?
                .error_for_status()
                .context(format!("failed to GET {url}"))?
                .text()
                .await
                .context(format!("failed to parse data from {url}"))?,
        };
        let aro = verify_request(wallet_profile, jwt, http_client)
            .await
            .context("unable to validate Authorization Request")?;
        if self.client_id.as_str() != aro.client_id().0.as_str() {
            bail!(
                "Authorization Request and Request Object have different client ids: '{}' vs. '{}'",
                self.client_id,
                aro.client_id().0
            );
        }
        Ok(aro)
    }

    /// Validate the [AuthorizationRequest] according to the client_id scheme and return the parsed
    /// [RequestObject].
    ///
    /// Custom wallet metadata can be provided, otherwise the default metadata for this profile is used.
    ///
    /// This method uses the library default http client to fetch the request object if it is passed by reference.
    pub async fn validate<WP: Wallet + ?Sized>(
        self,
        wallet_profile: &WP,
    ) -> Result<AuthorizationRequestObject> {
        self.validate_with_http_client(wallet_profile, &default_http_client()?)
            .await
    }

    /// Encode as [Url], using the `authorization_endpoint` as a base.
    /// ```
    /// # use oid4vp::core::authorization_request::AuthorizationRequest;
    /// # use oid4vp::core::authorization_request::RequestIndirection;
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
    /// # use oid4vp::core::authorization_request::AuthorizationRequest;
    /// # use oid4vp::core::authorization_request::RequestIndirection;
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
    /// # use oid4vp::core::authorization_request::AuthorizationRequest;
    /// # use oid4vp::core::authorization_request::RequestIndirection;
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
        &self.1
    }

    pub fn client_id_scheme(&self) -> &ClientIdScheme {
        &self.2
    }

    pub async fn resolve_presentation_definition_with_http_client(
        &self,
        http_client: reqwest::Client,
    ) -> Result<PresentationDefinition> {
        match &self.5 {
            PresentationDefinitionIndirection::ByValue(by_value) => Ok(by_value.clone()),
            PresentationDefinitionIndirection::ByReference(by_reference) => {
                let value: Json = http_client
                    .get(by_reference.clone())
                    .send()
                    .await
                    .context(format!(
                        "failed to GET Presentation Definition from '{by_reference}'"
                    ))?
                    .error_for_status()
                    .context(format!(
                        "failed to GET Presentation Definition from '{by_reference}'"
                    ))?
                    .json()
                    .await
                    .context(format!(
                        "response received from '{by_reference}' was not JSON"
                    ))?;
                value.try_into()
            }
        }
    }

    /// Uses the default library http client.
    pub async fn resolve_presentation_definition(&self) -> Result<PresentationDefinition> {
        self.resolve_presentation_definition_with_http_client(default_http_client()?)
            .await
    }

    pub fn is_id_token_requested(&self) -> Option<bool> {
        match self.4 {
            ResponseType::VpToken => Some(false),
            ResponseType::VpTokenIdToken => Some(true),
            ResponseType::Unsupported(_) => None,
        }
    }

    pub fn response_mode(&self) -> &ResponseMode {
        &self.3
    }

    pub fn response_type(&self) -> &ResponseType {
        &self.4
    }

    /// Uri to submit the response at.
    ///
    /// AKA [ResponseUri] or [RedirectUri] depending on [ResponseMode].
    pub fn return_uri(&self) -> &Url {
        &self.6
    }

    pub fn nonce(&self) -> &Nonce {
        &self.7
    }
}

impl From<AuthorizationRequestObject> for UntypedObject {
    fn from(value: AuthorizationRequestObject) -> Self {
        let mut inner = value.0;
        inner.insert(value.1);
        inner.insert(value.2);
        inner
    }
}

impl TryFrom<UntypedObject> for AuthorizationRequestObject {
    type Error = Error;

    fn try_from(value: UntypedObject) -> std::result::Result<Self, Self::Error> {
        let client_id = value.get().parsing_error()?;
        let client_id_scheme = value
            .get()
            .parsing_error()
            .context("this library cannot handle requests that omit client_id_scheme")?;

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
        };

        let response_type: ResponseType = value.get().parsing_error()?;

        let pd_indirection = match (
            value.get::<PresentationDefinition>(),
            value.get::<PresentationDefinitionUri>(),
        ) {
            (None, None) => bail!(
                "one of 'presentation_definition' and 'presentation_definition_uri' are required"
            ),
            (Some(_), Some(_)) => {
                bail!("'presentation_definition' and 'presentation_definition_uri' are mutually exclusive")
            }
            (Some(by_value), None) => {
                PresentationDefinitionIndirection::ByValue(by_value.parsing_error()?)
            }
            (None, Some(by_reference)) => {
                PresentationDefinitionIndirection::ByReference(by_reference.parsing_error()?.0)
            }
        };

        let nonce = value.get().parsing_error()?;

        Ok(Self(
            value,
            client_id,
            client_id_scheme,
            response_mode,
            response_type,
            pd_indirection,
            return_uri,
            nonce,
        ))
    }
}

impl Deref for AuthorizationRequestObject {
    type Target = UntypedObject;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AuthorizationRequestObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
