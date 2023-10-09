use anyhow::{Context, Error};

pub fn http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("unable to build http_client")
}
