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
    util::http_client,
};

/// A specific profile of OID4VP.
pub trait Profile {
    /// Credential Format used in this profile.
    type CredentialFormat: CredentialFormat;

    /// Builder for profile-specific [PresentationDefinition].
    type PresentationBuilder: PresentationBuilder;

    /// Perform additional profile-specific checks on outbound and inbound requests.
    fn validate_request(&self, request_object: &AuthorizationRequestObject) -> Result<(), Error>;
}

pub trait PresentationBuilder: Default {
    fn build(self) -> Result<PresentationDefinition, Error>;
}

#[async_trait]
pub trait WalletProfile: Profile + RequestVerification + Sync {
    type PresentationHandler: PresentationHandler;

    fn wallet_metadata(&self) -> &WalletMetadata;

    async fn to_handler(
        &self,
        request_object: &AuthorizationRequestObject,
    ) -> Result<Self::PresentationHandler, Error>;

    async fn handle_request(&self, url: Url) -> Result<Self::PresentationHandler, Error> {
        let ar =
            AuthorizationRequest::from_url(url, &self.wallet_metadata().authorization_endpoint().0)
                .context("unable to parse authorization request")?;
        let aro = ar
            .validate(self)
            .await
            .context("unable to validate authorization request")?;
        self.to_handler(&aro).await
    }

    async fn submit_response(
        &self,
        handler: Self::PresentationHandler,
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
                let response = http_client()?
                    .post(return_uri.clone())
                    .form(&body)
                    .header("Prefer", "OID4VP-0.0.20")
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
}

pub trait PresentationHandler: Send {
    fn request(&self) -> &AuthorizationRequestObject;
    fn to_response(self) -> Result<AuthorizationResponse, Error>;
}
