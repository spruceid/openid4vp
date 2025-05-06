use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use http::header::CONTENT_TYPE;
use url::Url;

use crate::core::{
    authorization_request::{
        parameters::ResponseMode, verification::RequestVerifier, AuthorizationRequest,
        AuthorizationRequestObject,
    },
    metadata::WalletMetadata,
    response::{AuthorizationResponse, PostRedirection},
    util::{base_request, AsyncHttpClient},
};

#[async_trait]
pub trait Wallet: RequestVerifier + Sync {
    type HttpClient: AsyncHttpClient + Send + Sync;

    fn metadata(&self) -> &WalletMetadata;
    fn http_client(&self) -> &Self::HttpClient;

    async fn validate_request(&self, url: Url) -> Result<AuthorizationRequestObject> {
        let ar = AuthorizationRequest::from_url(url, &self.metadata().authorization_endpoint().0)
            .context("unable to parse authorization request")?;
        ar.validate(self)
            .await
            .context("unable to validate authorization request")
    }

    async fn submit_response(
        &self,
        request: AuthorizationRequestObject,
        response: AuthorizationResponse,
    ) -> Result<Option<Url>> {
        let mut http_request_builder = base_request().uri(request.return_uri().as_str());

        let http_request_body = match request.response_mode() {
            ResponseMode::DirectPost => {
                http_request_builder = http_request_builder
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .method("POST");

                let AuthorizationResponse::Unencoded(unencoded) = response else {
                    bail!("unexpected AuthorizationResponse format")
                };

                unencoded.into_x_www_form_urlencoded()?.into_bytes()
            }
            ResponseMode::DirectPostJwt => {
                http_request_builder = http_request_builder
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .method("POST");

                let AuthorizationResponse::Jwt(jwt) = response else {
                    bail!("unexpected AuthorizationResponse format")
                };

                jwt.into_x_www_form_urlencoded()?.into_bytes()
            }
            ResponseMode::DcApi => {
                return Ok(None);
            }
            ResponseMode::DcApiJwt => {
                return Ok(None);
            }
            ResponseMode::Unsupported(rm) => bail!("unsupported response_mode {rm}"),
        };

        let http_request = http_request_builder
            .body(http_request_body)
            .context("failed to construct presentation submission request")?;
        let http_response = self
            .http_client()
            .execute(http_request)
            .await
            .context("failed to make authorization response request")?;

        let status = http_response.status();
        let Ok(body) = String::from_utf8(http_response.into_body()) else {
            bail!("failed to parse authorization response response as UTF-8 (status: {status})")
        };

        if !status.is_success() {
            bail!("authorization response request was unsuccessful (status: {status}): {body}")
        }

        Ok(serde_json::from_str(&body)
            .ok()
            .map(|PostRedirection { redirect_uri }| redirect_uri))
    }
}
