use anyhow::{bail, Context, Error};
use async_trait::async_trait;
use tracing::warn;
use url::Url;

use super::{
    authorization_request::{
        parameters::{PresentationDefinition, ResponseMode},
        verification::RequestVerification,
        AuthorizationRequest, AuthorizationRequestObject,
    },
    credential_format::CredentialFormat,
    metadata::WalletMetadata,
    response::{AuthorizationResponse, PostRedirection},
    util::default_http_client,
};

/// A specific profile of OID4VP.
pub trait Profile {
    /// Credential Format used in this profile.
    type CredentialFormat: CredentialFormat;

    /// Perform additional profile-specific checks on outbound and inbound requests.
    fn validate_request(
        &self,
        wallet_metadata: &WalletMetadata,
        request_object: &AuthorizationRequestObject,
    ) -> Result<(), Error>;
}

pub trait Verifier: Profile {
    /// Builder for profile-specific [PresentationDefinition].
    type PresentationBuilder: PresentationBuilder;
}

pub trait PresentationBuilder: Default {
    fn build(self) -> Result<PresentationDefinition, Error>;
}

#[async_trait]
pub trait Wallet: Profile + RequestVerification + Sync {
    type PresentationHandler: PresentationHandler;

    fn wallet_metadata(&self) -> &WalletMetadata;

    async fn to_handler(
        &self,
        request_object: &AuthorizationRequestObject,
    ) -> Result<Self::PresentationHandler, Error>;

    async fn handle_request_with_http_client(
        &self,
        url: Url,
        http_client: &reqwest::Client,
    ) -> Result<Self::PresentationHandler, Error> {
        let ar =
            AuthorizationRequest::from_url(url, &self.wallet_metadata().authorization_endpoint().0)
                .context("unable to parse authorization request")?;
        let aro = ar
            .validate_with_http_client(self, http_client)
            .await
            .context("unable to validate authorization request")?;
        self.to_handler(&aro).await
    }

    /// Uses library default http client.
    async fn handle_request(&self, url: Url) -> Result<Self::PresentationHandler, Error> {
        self.handle_request_with_http_client(url, &default_http_client()?)
            .await
    }

    async fn submit_response_with_http_client(
        &self,
        handler: Self::PresentationHandler,
        http_client: reqwest::Client,
    ) -> Result<Option<Url>, Error> {
        let aro = handler.request().clone();
        let response_object = handler.to_response()?;
        let return_uri = aro.return_uri();
        match aro.response_mode() {
            ResponseMode::DirectPost => {
                let body = response_object
                    .serializable()
                    .flatten_for_form()
                    .context("unable to flatten authorization response")?;
                let response = http_client
                    .post(return_uri.clone())
                    .form(&body)
                    .send()
                    .await
                    .context("failed to post authorization response")?;

                let status = response.status();
                let text = response.text().await.context("text")?;

                if !status.is_success() {
                    bail!("error submitting authorization response ({status}): {text}")
                }

                Ok(serde_json::from_str(&text)
                    .map_err(|e| warn!("response did not contain a redirect: {e}"))
                    .ok()
                    .map(|PostRedirection { redirect_uri }| redirect_uri))
            }
            ResponseMode::DirectPostJwt => todo!(),
            ResponseMode::Unsupported(rm) => bail!("unsupported response_mode {rm}"),
        }
    }

    /// Uses library default http client.
    async fn submit_response(
        &self,
        handler: Self::PresentationHandler,
    ) -> Result<Option<Url>, Error> {
        self.submit_response_with_http_client(handler, default_http_client()?)
            .await
    }
}

pub trait PresentationHandler: Send {
    fn request(&self) -> &AuthorizationRequestObject;
    fn to_response(self) -> Result<AuthorizationResponse, Error>;
}
