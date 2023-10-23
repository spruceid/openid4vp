use crate::core::{
    metadata::{
        parameters::{
            verifier::{AuthorizationEncryptedResponseAlg, AuthorizationEncryptedResponseEnc},
            wallet::{
                AuthorizationEncryptionAlgValuesSupported,
                AuthorizationEncryptionEncValuesSupported,
            },
        },
        WalletMetadata,
    },
    object::{ParsingErrorContext, TypedParameter, UntypedObject},
    profile::{Profile, Wallet},
};
use anyhow::{bail, Context, Error, Result};
use async_trait::async_trait;

use super::{
    parameters::{ClientIdScheme, ClientMetadata, ResponseMode},
    AuthorizationRequestObject,
};

pub mod did;
pub mod x509_san_dns;
pub mod x509_san_uri;

/// Verifies Authorization Request Objects.
#[async_trait]
pub trait RequestVerification {
    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `did`.
    ///
    /// See default implementation [did].
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error>;

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `entity_id`.
    async fn entity_id(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error>;

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `pre-registered`.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error>;

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `redirect_uri`.
    ///
    /// See default implementation [redirect_uri].
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error>;

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_dns`.
    ///
    /// See default implementation [x509_san_uri].
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error>;

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_uri`.
    ///
    /// See default implementation [x509_san_uri].
    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error>;

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is any other value.
    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error>;
}

pub(crate) async fn verify_request<WP: Wallet + ?Sized>(
    profile: &WP,
    jwt: String,
    http_client: &reqwest::Client,
) -> Result<AuthorizationRequestObject> {
    let request: AuthorizationRequestObject = ssi::jwt::decode_unverified::<UntypedObject>(&jwt)
        .context("unable to decode Authorization Request Object JWT")?
        .try_into()?;

    validate_request_against_metadata::<WP>(
        profile,
        &request,
        profile.wallet_metadata(),
        http_client,
    )
    .await?;

    let client_id_scheme = request.client_id_scheme();

    match client_id_scheme {
        ClientIdScheme::Did => profile.did(&request, jwt).await?,
        ClientIdScheme::EntityId => profile.entity_id(&request, jwt).await?,
        ClientIdScheme::PreRegistered => profile.preregistered(&request, jwt).await?,
        ClientIdScheme::RedirectUri => profile.redirect_uri(&request, jwt).await?,
        ClientIdScheme::X509SanDns => profile.x509_san_dns(&request, jwt).await?,
        ClientIdScheme::X509SanUri => profile.x509_san_uri(&request, jwt).await?,
        ClientIdScheme::Other(scheme) => profile.other(scheme, &request, jwt).await?,
    };

    Ok(request)
}

pub(crate) async fn validate_request_against_metadata<P: Profile + ?Sized>(
    profile: &P,
    request: &AuthorizationRequestObject,
    wallet_metadata: &WalletMetadata,
    http_client: &reqwest::Client,
) -> Result<(), Error> {
    let client_id_scheme = request.client_id_scheme();
    if !wallet_metadata
        .client_id_schemes_supported()
        .0
        .contains(client_id_scheme)
    {
        bail!(
            "wallet does not support client_id_scheme '{}'",
            client_id_scheme
        )
    }

    let client_metadata = ClientMetadata::resolve_with_http_client(request, http_client)
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

    profile
        .validate_request(wallet_metadata, request)
        .context("unable to validate request according to profile-specific checks:")
}
