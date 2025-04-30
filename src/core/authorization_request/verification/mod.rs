use crate::{
    core::{
        metadata::parameters::{
            verifier::{AuthorizationEncryptedResponseAlg, AuthorizationEncryptedResponseEnc},
            wallet::{
                AuthorizationEncryptionAlgValuesSupported,
                AuthorizationEncryptionEncValuesSupported, ClientIdSchemesSupported,
            },
        },
        object::{ParsingErrorContext, TypedParameter},
    },
    wallet::Wallet,
};
use anyhow::{bail, Error, Result};
use async_trait::async_trait;

use super::{
    parameters::{ClientIdScheme, ClientMetadata, ResponseMode},
    AuthorizationRequestObject,
};

pub mod did;
pub mod verifier;
pub mod x509_san;

/// Verifies Authorization Request Objects.
#[allow(unused_variables)]
#[async_trait]
pub trait RequestVerifier {
    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `did`.
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'did' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `entity_id` or `https`.
    async fn openid_federation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("openid federation client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `pre-registered`.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'pre-registered' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `redirect_uri`.
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'redirect_uri' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `verifier_attestation`.
    async fn verifier_attestation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'verifier_attestation' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `web-origin`.
    async fn web_origin(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'web-origin' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_dns`.
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'x509_san_dns' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_uri`.
    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'x509_san_uri' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is any other value.
    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'{client_id_scheme}' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when there is no `client_id_scheme`.
    async fn none(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("client_id_scheme is required")
    }
}

pub(crate) async fn verify_request<W: Wallet + ?Sized>(
    wallet: &W,
    decoded_request: &AuthorizationRequestObject,
    jwt: Option<String>,
) -> Result<()> {
    validate_request_against_metadata(wallet, decoded_request).await?;

    let client_id_scheme = decoded_request.client_id_scheme();

    match client_id_scheme.map(|scheme| scheme.0.as_str()) {
        Some(ClientIdScheme::DID) => wallet.did(decoded_request, jwt).await?,
        Some(ClientIdScheme::ENTITY_ID) => wallet.openid_federation(decoded_request, jwt).await?,
        Some(ClientIdScheme::HTTPS) => wallet.openid_federation(decoded_request, jwt).await?,
        Some(ClientIdScheme::PREREGISTERED) => wallet.preregistered(decoded_request, jwt).await?,
        Some(ClientIdScheme::REDIRECT_URI) => wallet.redirect_uri(decoded_request, jwt).await?,
        Some(ClientIdScheme::VERIFIER_ATTESTATION) => {
            wallet.verifier_attestation(decoded_request, jwt).await?
        }
        Some(ClientIdScheme::WEB_ORIGIN) => wallet.web_origin(decoded_request, jwt).await?,
        Some(ClientIdScheme::X509_SAN_DNS) => wallet.x509_san_dns(decoded_request, jwt).await?,
        Some(ClientIdScheme::X509_SAN_URI) => wallet.x509_san_uri(decoded_request, jwt).await?,
        Some(scheme) => wallet.other(scheme, decoded_request, jwt).await?,
        None => wallet.none(decoded_request, jwt).await?,
    };

    Ok(())
}

pub(crate) async fn validate_request_against_metadata<W: Wallet + ?Sized>(
    wallet: &W,
    request: &AuthorizationRequestObject,
) -> Result<(), Error> {
    let wallet_metadata = wallet.metadata();

    if let Some(client_id_scheme) = request.client_id_scheme() {
        if !wallet_metadata
            .get_or_default::<ClientIdSchemesSupported>()?
            .0
            .contains(&client_id_scheme)
        {
            bail!(
                "wallet does not support client_id_scheme '{}'",
                client_id_scheme.0
            )
        }
    }

    let client_metadata = ClientMetadata::resolve(request, wallet.http_client())
        .await?
        .0;

    let response_mode = request.get::<ResponseMode>().parsing_error()?;

    if response_mode.is_jarm()? {
        let alg = client_metadata
            .get::<AuthorizationEncryptedResponseAlg>()
            .parsing_error()?;
        let enc = client_metadata
            .get::<AuthorizationEncryptedResponseEnc>()
            .parsing_error()?;

        if let Some(supported_algs) =
            wallet_metadata.get::<AuthorizationEncryptionAlgValuesSupported>()
        {
            if !supported_algs?.0.contains(&alg.0) {
                bail!(
                    "unsupported {} '{}'",
                    AuthorizationEncryptedResponseAlg::KEY,
                    alg.0
                )
            }
        }
        if let Some(supported_encs) =
            wallet_metadata.get::<AuthorizationEncryptionEncValuesSupported>()
        {
            if !supported_encs?.0.contains(&enc.0) {
                bail!(
                    "unsupported {} '{}'",
                    AuthorizationEncryptedResponseEnc::KEY,
                    enc.0
                )
            }
        }
    }

    Ok(())
}
