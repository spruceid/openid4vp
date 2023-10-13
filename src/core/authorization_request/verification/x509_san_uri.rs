use anyhow::{bail, Context, Error, Result};
use base64::prelude::*;
use p256::ecdsa::signature::Verifier as _;
use serde_json::{Map, Value as Json};
use tracing::{debug, warn};
use x509_cert::{
    der::{referenced::OwnedToRef, Decode},
    ext::pkix::{name::GeneralName, SubjectAltName},
    spki::SubjectPublicKeyInfoRef,
    Certificate,
};

use crate::core::{
    authorization_request::AuthorizationRequestObject,
    metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
    object::ParsingErrorContext,
};

/// Default implementation of request validation for `client_id_scheme` `x509_san_uri`.
pub fn validate<V: Verifier>(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_roots: Option<&[Certificate]>,
) -> Result<()> {
    let client_id = request_object.client_id().0.as_str();
    let (headers_b64, body_b64, sig_b64) = ssi::jws::split_jws(&request_jwt)?;

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

    let Json::String(b64_x509) = x5chain.get(0).context("'x5c' was an empty array")? else {
        bail!("'x5c' header was not an array of strings");
    };

    let leaf_cert_der = BASE64_STANDARD_NO_PAD
        .decode(b64_x509.trim_end_matches('='))
        .context("leaf certificate in 'x5c' was not valid base64")?;

    let leaf_cert = Certificate::from_der(&leaf_cert_der)
        .context("leaf certificate in 'x5c' was not valid DER")?;

    // NOTE: Fallback to common name is removed in latest drafts of OID4VP.
    if leaf_cert.tbs_certificate.get::<SubjectAltName>() == Ok(None) {
        warn!("x509 certificate does not contain Subject Alternative Name, falling back to Common Name");
        if !leaf_cert
            .tbs_certificate
            .subject
            .0
            .iter()
            .flat_map(|n| n.0.iter())
            .filter_map(|n| n.to_string().strip_prefix("CN=").map(ToOwned::to_owned))
            .any(|cn| cn == client_id)
        {
            bail!("client_id does not match Common Name and x509 certificate does not contain Subject Alternative Name")
        }
    } else if !leaf_cert
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
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
            _ => {
                debug!("found non-URI SAN: {gn:?}");
                None
            }
        })
        .any(|uri| uri == client_id)
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

pub trait Verifier: Sized {
    /// Construct a [Verifier] from [SubjectPublicKeyInfoRef].
    ///
    /// ## Params
    /// * `spki` - the public key information necessary to construct a [Verifier].
    /// * `algorithm` - the value taken from the `alg` header of the request, to hint at what curve should be used by the [Verifier].
    fn from_spki(spki: SubjectPublicKeyInfoRef<'_>, algorithm: String) -> Result<Self>;
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct P256Verifier(p256::ecdsa::VerifyingKey);

impl Verifier for P256Verifier {
    fn from_spki(spki: SubjectPublicKeyInfoRef<'_>, algorithm: String) -> Result<Self> {
        if algorithm != "ES256" {
            bail!("P256Verifier cannot verify requests signed with '{algorithm}'")
        }
        spki.try_into().map(Self).map_err(Error::from)
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let signature = p256::ecdsa::Signature::from_slice(signature)?;
        self.0.verify(payload, &signature).map_err(Error::from)
    }
}
