use anyhow::{bail, Context, Result};
use base64::prelude::*;
use sha2::{Digest, Sha256};
use tracing::debug;
use x509_cert::{
    Certificate, der::Encode,
};

use crate::core::{
    authorization_request::{parameters::ClientIdScheme, AuthorizationRequestObject, verification::x509::{get_header_certificate,validate_chain_and_signature}},
    metadata::WalletMetadata,
};

use super::verifier::Verifier;

/// Default implementation of request validation for `x509_hash` Client Identifier Prefix.
/// Per OID4VP v1.0 Section 5.9.3.
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
    let (chain, alg) = get_header_certificate(wallet_metadata,&request_jwt)?;

    // Strip prefix if present
    let client_id = request_object
        .client_id()
        .context("client_id is required")?;
    let expected_hash = client_id
        .0
        .strip_prefix(&format!("{}:", ClientIdScheme::X509_HASH))
        .unwrap_or(&client_id.0);

    // Compute SHA-256 hash of the DER-encoded certificate and base64url encode
    let leaf = chain.first().context("'x5c' was empty")?;
    let computed_hash = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(leaf.to_der()?));

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

    validate_chain_and_signature::<V>(&chain, trusted_roots, alg, request_jwt)
}
