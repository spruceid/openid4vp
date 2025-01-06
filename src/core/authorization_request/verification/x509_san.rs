use anyhow::{bail, Context, Result};
use base64::prelude::*;
use serde_json::{Map, Value as Json};
use tracing::debug;
use x509_cert::{
    der::{referenced::OwnedToRef, Decode},
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::{
    core::{
        authorization_request::AuthorizationRequestObject,
        metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
        object::ParsingErrorContext,
    },
    verifier::client::X509SanVariant,
};

use super::verifier::Verifier;

/// Default implementation of request validation for `client_id_scheme` `x509_san_dns`.
pub fn validate<V: Verifier>(
    x509_san_variant: X509SanVariant,
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_roots: Option<&[Certificate]>,
) -> Result<()> {
    let client_id = request_object.client_id().0.as_str();
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
        .filter_map(|gn| match (gn, x509_san_variant) {
            (GeneralName::DnsName(uri), X509SanVariant::Dns) => Some(uri.to_string()),
            (GeneralName::UniformResourceIdentifier(uri), X509SanVariant::Uri) => {
                Some(uri.to_string())
            }
            #[cfg(feature = "maximize_interoperability")]
            (GeneralName::DnsName(uri), X509SanVariant::Uri) => Some(uri.to_string()),
            #[cfg(feature = "maximize_interoperability")]
            (GeneralName::UniformResourceIdentifier(uri), X509SanVariant::Dns) => Some(
                url::Url::parse(uri.as_str())
                    .map(|u| u.authority().to_string())
                    .unwrap_or(uri.to_string()),
            ),
            (gn, X509SanVariant::Dns) => {
                debug!("found non-DNS SAN: {gn:?}");
                None
            }
            (gn, X509SanVariant::Uri) => {
                debug!("found non-URI SAN: {gn:?}");
                None
            }
        })
        .any(|uri| {
            debug!("comparing SAN '{uri}' to client_id '{client_id}'");
            uri == client_id
        })
    {
        bail!("client_id does not match any Subject Alternative Name")
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
