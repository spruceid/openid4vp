use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use http::{Request, Response};

/// Generic HTTP client.
///
/// A trait is used here so to facilitate native HTTP/TLS when compiled for mobile applications.
#[async_trait]
pub trait AsyncHttpClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>>;
}

pub(crate) fn base_request() -> http::request::Builder {
    Request::builder().header("Prefer", "OID4VP-0.0.20")
}

#[derive(Debug)]
pub struct ReqwestClient(reqwest::Client);

impl AsRef<reqwest::Client> for ReqwestClient {
    fn as_ref(&self) -> &reqwest::Client {
        &self.0
    }
}

impl ReqwestClient {
    pub fn new() -> Result<Self> {
        reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .context("unable to build http_client")
            .map(Self)
    }
}

#[async_trait]
impl AsyncHttpClient for ReqwestClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        let response = self
            .0
            .execute(request.try_into().context("unable to convert request")?)
            .await
            .context("http request failed")?;

        let mut builder = Response::builder()
            .status(response.status())
            .version(response.version());

        builder
            .extensions_mut()
            .context("unable to set extensions")?
            .extend(response.extensions().clone());

        builder
            .headers_mut()
            .context("unable to set headers")?
            .extend(response.headers().clone());

        builder
            .body(
                response
                    .bytes()
                    .await
                    .context("failed to extract response body")?
                    .to_vec(),
            )
            .context("unable to construct response")
    }
}

#[cfg(test)]
mod test {
    use http::Response;

    #[test]
    fn debug() {
        Response::builder().extensions_mut().unwrap();
        Response::builder().headers_mut().unwrap();
    }
}
