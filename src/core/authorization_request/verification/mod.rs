use crate::{
    core::{
        metadata::parameters::{
            verifier::{EncryptedResponseEncValuesSupported, JWKs},
            wallet::{
                AuthorizationEncryptionAlgValuesSupported,
                AuthorizationEncryptionEncValuesSupported, ClientIdPrefixesSupported,
            },
        },
        object::ParsingErrorContext,
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
pub mod x509_hash;
pub mod x509_san;

/// Verifies Authorization Request Objects based on Client Identifier Prefix.
///
/// Per OID4VP v1.0 Section 5.9, the Client Identifier Prefix determines how the
/// Wallet validates the Verifier's identity and the Authorization Request.
#[allow(unused_variables)]
#[async_trait]
pub trait RequestVerifier {
    /// Performs verification when the Client Identifier Prefix is `decentralized_identifier`.
    /// Per Section 5.9.3, the request MUST be signed with a private key associated with the DID.
    async fn decentralized_identifier(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'decentralized_identifier' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `openid_federation`.
    async fn openid_federation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'openid_federation' client verification not implemented")
    }

    /// Performs verification for pre-registered clients.
    ///
    /// Per Section 5.9.2, if no `:` is present in the client_id, or if an unrecognized
    /// prefix is present, the client is treated as pre-registered. The Verifier metadata
    /// is obtained using RFC7591 or through out-of-band mechanisms.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'pre-registered' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `redirect_uri`.
    /// Per Section 5.9.3, requests using this prefix cannot be signed.
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'redirect_uri' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `verifier_attestation`.
    async fn verifier_attestation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'verifier_attestation' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `x509_san_dns`.
    /// Per Section 5.9.3, the request MUST be signed with the private key corresponding
    /// to the public key in the leaf X.509 certificate.
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'x509_san_dns' client verification not implemented")
    }

    /// Performs verification when the Client Identifier Prefix is `x509_hash`.
    /// Per Section 5.9.3, the request MUST be signed with the private key corresponding
    /// to the public key in the leaf X.509 certificate.
    async fn x509_hash(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'x509_hash' client verification not implemented")
    }

    /// Performs verification for custom/extension Client Identifier Prefixes.
    ///
    /// Per Section 5.9.3, other specifications can define further Client Identifier Prefixes.
    /// Per Section 5.9.2, if the prefix is not recognized, the Wallet can either treat the
    /// client as pre-registered or refuse the request.
    async fn other(
        &self,
        prefix: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<(), Error> {
        bail!("'{prefix}' client verification not implemented")
    }
}

pub(crate) async fn verify_request<W: Wallet + ?Sized>(
    wallet: &W,
    decoded_request: &AuthorizationRequestObject,
    jwt: Option<String>,
) -> Result<()> {
    validate_request_against_metadata(wallet, decoded_request).await?;

    // Get the Client Identifier Prefix from client_id
    // Per Section 5.9.2: If no ':' is present, treat as pre-registered
    let client_id_prefix = decoded_request.client_id_scheme();

    match client_id_prefix.map(|prefix| prefix.0.as_str()) {
        Some(ClientIdScheme::DECENTRALIZED_IDENTIFIER) => {
            wallet
                .decentralized_identifier(decoded_request, jwt)
                .await?
        }
        Some(ClientIdScheme::OPENID_FEDERATION) => {
            wallet.openid_federation(decoded_request, jwt).await?
        }
        Some(ClientIdScheme::REDIRECT_URI) => wallet.redirect_uri(decoded_request, jwt).await?,
        Some(ClientIdScheme::VERIFIER_ATTESTATION) => {
            wallet.verifier_attestation(decoded_request, jwt).await?
        }
        Some(ClientIdScheme::X509_SAN_DNS) => wallet.x509_san_dns(decoded_request, jwt).await?,
        Some(ClientIdScheme::X509_HASH) => wallet.x509_hash(decoded_request, jwt).await?,
        Some(ClientIdScheme::ORIGIN) => {
            bail!("'origin' Client Identifier Prefix is reserved for Digital Credentials API and MUST NOT be accepted")
        }
        Some(prefix) => {
            // Per Section 5.9.2: If prefix is not recognized, the Wallet can treat
            // the Client Identifier as referring to a pre-registered client or refuse.
            // Here we delegate to the `other` method to let the implementation decide.
            wallet.other(prefix, decoded_request, jwt).await?
        }
        None => {
            // Per Section 5.9.2: If no ':' is present, treat as pre-registered client
            wallet.preregistered(decoded_request, jwt).await?
        }
    };

    Ok(())
}

pub(crate) async fn validate_request_against_metadata<W: Wallet + ?Sized>(
    wallet: &W,
    request: &AuthorizationRequestObject,
) -> Result<(), Error> {
    let wallet_metadata = wallet.metadata();

    // Validate that the wallet supports the Client Identifier Prefix (if present)
    // Per Section 5.9.2: If no ':' is present, treat as pre-registered (no prefix to validate)
    if let Some(prefix) = request.client_id_scheme() {
        if !wallet_metadata
            .get_or_default::<ClientIdPrefixesSupported>()?
            .0
            .contains(prefix)
        {
            bail!(
                "wallet does not support Client Identifier Prefix '{}'",
                prefix.0
            )
        }
    }

    let client_metadata = ClientMetadata::resolve(request)?.0;

    let response_mode = request.get::<ResponseMode>().parsing_error()?;

    // Validate encrypted response parameters per OID4VP v1.0 Section 8.3
    // For JARM (encrypted responses), the verifier provides:
    // - `alg` in each JWK within `jwks` (MUST be present)
    // - `enc` via `encrypted_response_enc_values_supported` (default: A128GCM)
    if response_mode.is_jarm()? {
        // Get JWKs from client_metadata - required for encrypted responses
        let jwks = client_metadata
            .get::<JWKs>()
            .ok_or_else(|| anyhow::anyhow!("'jwks' is required for encrypted responses"))?
            .map_err(|e| anyhow::anyhow!("failed to parse 'jwks': {e}"))?;

        // Find encryption keys (use="enc") and extract their alg values
        let encryption_algs: Vec<String> = jwks
            .keys
            .iter()
            .filter(|k| {
                k.get("use")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "enc")
                    .unwrap_or(false)
            })
            .filter_map(|k| k.get("alg").and_then(|v| v.as_str()).map(String::from))
            .collect();

        if encryption_algs.is_empty() {
            bail!(
                "no encryption key with 'alg' found in jwks (required per OID4VP v1.0 Section 8.3)"
            )
        }

        // Validate alg against wallet supported values
        if let Some(supported_algs) =
            wallet_metadata.get::<AuthorizationEncryptionAlgValuesSupported>()
        {
            let supported = supported_algs?;
            let has_supported_alg = encryption_algs.iter().any(|alg| supported.0.contains(alg));
            if !has_supported_alg {
                bail!(
                    "none of the encryption algorithms in jwks ({:?}) are supported by the wallet ({:?})",
                    encryption_algs,
                    supported.0
                )
            }
        }

        // Get enc values from encrypted_response_enc_values_supported (default: A128GCM)
        let enc_values = client_metadata
            .get::<EncryptedResponseEncValuesSupported>()
            .transpose()?
            .unwrap_or_default();

        // Validate enc against wallet supported values
        if let Some(supported_encs) =
            wallet_metadata.get::<AuthorizationEncryptionEncValuesSupported>()
        {
            let supported = supported_encs?;
            let has_supported_enc = enc_values.0.iter().any(|enc| supported.0.contains(enc));
            if !has_supported_enc {
                bail!(
                    "none of the content encryption algorithms ({:?}) are supported by the wallet ({:?})",
                    enc_values.0,
                    supported.0
                )
            }
        }
    }

    Ok(())
}
