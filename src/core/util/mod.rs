use anyhow::{Context, Error};
use reqwest::header::HeaderMap;

pub fn default_http_client() -> Result<reqwest::Client, Error> {
    let mut headers: HeaderMap = Default::default();
    headers.insert(
        "Prefer",
        "OID4VP-0.0.20"
            .parse()
            .context("unable to parse Prefer header value")?,
    );

    reqwest::Client::builder()
        .default_headers(headers)
        .use_rustls_tls()
        .build()
        .context("unable to build http_client")
}
