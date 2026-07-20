use anyhow::{bail, Context, Result};
use tracing::debug;
use x509_cert::{
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::core::{
    authorization_request::{parameters::ClientIdScheme, AuthorizationRequestObject,verification::x509::{get_header_certificate,validate_chain_and_signature}},
    metadata::WalletMetadata
};

use super::verifier::Verifier;

/// Default implementation of request validation for `x509_san_dns` Client Identifier Prefix.
/// Per OID4VP v1.0 Section 5.9.3.
pub fn validate<V: Verifier>(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_roots: Option<&[Certificate]>,
) -> Result<()> {
    let (chain,  alg) = get_header_certificate(wallet_metadata,&request_jwt)?;
    // Strip prefix if present
    let client_id = request_object
        .client_id()
        .context("client_id is required")?;
    let client_id_source = client_id
        .0
        .strip_prefix(&format!("{}:", ClientIdScheme::X509_SAN_DNS))
        .unwrap_or(&client_id.0);

    let leaf_cert = chain.first().context("'x5c' certificate chain was empty")?;
    if !leaf_cert
        .tbs_certificate
        .filter::<SubjectAltName>()
        .filter_map(|r| match r {
            Ok((_crit, san)) => Some(san.0.into_iter()),
            Err(e) => {
                debug!("unable to parse SubjectAlternativeName from DER: {e}");
                None
            }
        })
        .flatten()
        .filter_map(|gn| match gn {
            GeneralName::DnsName(dns) => Some(dns.to_string()),
            gn => {
                debug!("found non-DNS SAN: {gn:?}");
                None
            }
        })
        .any(|dns| {
            debug!("comparing SAN '{dns}' to client_id '{client_id_source}'");
            dns == client_id_source
        })
    {
        bail!("client_id does not match any DNS Subject Alternative Name")
    }

    validate_chain_and_signature::<V>(&chain, trusted_roots, alg, request_jwt)
}