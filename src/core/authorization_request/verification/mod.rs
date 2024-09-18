use crate::{
    core::{
        metadata::parameters::{
            verifier::{AuthorizationEncryptedResponseAlg, AuthorizationEncryptedResponseEnc},
            wallet::{
                AuthorizationEncryptionAlgValuesSupported,
                AuthorizationEncryptionEncValuesSupported, ClientIdSchemesSupported,
            },
        },
        object::{ParsingErrorContext, TypedParameter, UntypedObject},
    },
    wallet::Wallet,
};
use anyhow::{bail, Context, Error, Result};
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
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'did' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `entity_id`.
    async fn entity_id(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'entity' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `pre-registered`.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'pre-registered' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `redirect_uri`.
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'redirect_uri' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `verifier_attestation`.
    async fn verifier_attestation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'verifier_attestation' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_dns`.
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'x509_san_dns' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_uri`.
    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'x509_san_uri' client verification not implemented")
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is any other value.
    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        bail!("'{client_id_scheme}' client verification not implemented")
    }
}

pub(crate) async fn verify_request<W: Wallet + ?Sized>(
    wallet: &W,
    jwt: String,
) -> Result<AuthorizationRequestObject> {
    let request: AuthorizationRequestObject =
        ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
            .context("unable to decode Authorization Request Object JWT")?
            .try_into()?;

    validate_request_against_metadata(wallet, &request).await?;

    let client_id_scheme = request.client_id_scheme();

    match client_id_scheme {
        ClientIdScheme::Did => wallet.did(&request, jwt).await?,
        ClientIdScheme::EntityId => wallet.entity_id(&request, jwt).await?,
        ClientIdScheme::PreRegistered => wallet.preregistered(&request, jwt).await?,
        ClientIdScheme::RedirectUri => wallet.redirect_uri(&request, jwt).await?,
        ClientIdScheme::VerifierAttestation => wallet.verifier_attestation(&request, jwt).await?,
        ClientIdScheme::X509SanDns => wallet.x509_san_dns(&request, jwt).await?,
        ClientIdScheme::X509SanUri => wallet.x509_san_uri(&request, jwt).await?,
        ClientIdScheme::Other(scheme) => wallet.other(scheme, &request, jwt).await?,
    };

    Ok(request)
}

pub(crate) async fn validate_request_against_metadata<W: Wallet + ?Sized>(
    wallet: &W,
    request: &AuthorizationRequestObject,
) -> Result<(), Error> {
    let wallet_metadata = wallet.metadata();

    let client_id_scheme = request.client_id_scheme();
    if !wallet_metadata
        .get_or_default::<ClientIdSchemesSupported>()?
        .0
        .contains(client_id_scheme)
    {
        bail!(
            "wallet does not support client_id_scheme '{}'",
            client_id_scheme
        )
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
