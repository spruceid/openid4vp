use anyhow::{bail, Context, Result};
use base64::prelude::*;
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};
use tracing::debug;
use x509_cert::{
    der::{referenced::OwnedToRef, Decode},
    Certificate,
};

use crate::core::{
    authorization_request::{parameters::ClientIdScheme, AuthorizationRequestObject},
    metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
    object::ParsingErrorContext,
};

use super::verifier::Verifier;

/// Default implementation of request validation for `client_id_scheme` `x509_hash`.
///
/// This validates that:
/// 1. The JWT header contains an `x5c` array with at least one certificate
/// 2. The base64url-encoded SHA-256 hash of the leaf certificate matches the client_id
/// 3. The JWT signature is valid using the leaf certificate's public key
///
/// # Arguments
///
/// * `wallet_metadata` - The wallet's metadata, used to check supported signing algorithms
/// * `request_object` - The decoded authorization request object
/// * `request_jwt` - The original JWT string
/// * `trusted_roots` - Optional trusted root certificates for chain validation (not yet implemented)
pub fn validate<V: Verifier>(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_roots: Option<&[Certificate]>,
) -> Result<()> {
    let client_id = request_object
        .client_id()
        .context("client_id is required")?;

    // Strip the "x509_hash:" prefix if present
    let expected_hash = client_id
        .0
        .strip_prefix(&format!("{}:", ClientIdScheme::X509_HASH))
        .unwrap_or(&client_id.0);

    let (headers_b64, body_b64, sig_b64) = ssi::claims::jws::split_jws(&request_jwt)?;

    let headers_json_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(headers_b64)
        .context("jwt headers were not valid base64url")?;

    let mut headers = serde_json::from_slice::<Map<String, Json>>(&headers_json_bytes)
        .context("jwt headers were not valid json")?;

    let Json::String(alg) = headers
        .remove("alg")
        .context("'alg' was missing from jwt headers")?
    else {
        bail!("'alg' header was not a string")
    };

    let supported_algs: RequestObjectSigningAlgValuesSupported =
        wallet_metadata.get().parsing_error()?;

    if !supported_algs.0.contains(&alg) {
        bail!("request was signed with unsupported algorithm: {alg}")
    }

    let Json::Array(x5chain) = headers
        .remove("x5c")
        .context("'x5c' was missing from jwt headers")?
    else {
        bail!("'x5c' header was not an array")
    };

    let Json::String(b64_x509) = x5chain.first().context("'x5c' was an empty array")? else {
        bail!("'x5c' header was not an array of strings");
    };

    let leaf_cert_der = BASE64_STANDARD_NO_PAD
        .decode(b64_x509.trim_end_matches('='))
        .context("leaf certificate in 'x5c' was not valid base64")?;

    let leaf_cert = Certificate::from_der(&leaf_cert_der)
        .context("leaf certificate in 'x5c' was not valid DER")?;

    debug!("Leaf certificate: {leaf_cert:?}");

    // Compute SHA-256 hash of the DER-encoded certificate and base64url encode
    let computed_hash = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(&leaf_cert_der));

    debug!(
        "x509_hash verification: expected='{}', computed='{}'",
        expected_hash, computed_hash
    );

    if computed_hash != expected_hash {
        bail!(
            "client_id hash '{}' does not match certificate hash '{}'",
            expected_hash,
            computed_hash
        );
    }

    if let Some(_trusted_roots) = trusted_roots {
        // TODO: Verify chain to root.
    }

    let verifier = V::from_spki(
        leaf_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref(),
        alg,
    )
    .context("unable to parse SPKI")?;

    let payload = [headers_b64.as_bytes(), b".", body_b64.as_bytes()].concat();
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(sig_b64)
        .context("could not decode base64url encoded jwt signature")?;

    verifier
        .verify(&payload, &signature)
        .context("request signature could not be verified")?;

    Ok(())
}
