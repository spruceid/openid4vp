use anyhow::{bail, Context, Result};
use base64::prelude::*;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use serde_json::{Map, Value as Json};
use tracing::debug;
use x509_cert::{
    Certificate, certificate::CertificateInner, der::{Decode, Encode, referenced::OwnedToRef}, ext::pkix::BasicConstraints,
};

use crate::core::{
    metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
    object::ParsingErrorContext,
};

use super::verifier::{P256Verifier, P384Verifier, RsaVerifier, Verifier};

pub fn get_header_certificate(
    wallet_metadata: &WalletMetadata,
    request_jwt: &str,
) -> Result<(Vec<CertificateInner>,String)> {
    let (headers_b64, _body_b64, _sig_b64) = ssi::claims::jws::split_jws(request_jwt)?;

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

    // Decode full chain
    let chain = x5chain
        .iter()
        .map(|value| {
            let b64 = value
                .as_str()
                .context("certificate in 'x5c' was not a string")?;
            let der = BASE64_STANDARD_NO_PAD
                .decode(b64.trim_end_matches('='))
                .context("certificate in 'x5c' was not valid base64")?;
            Certificate::from_der(&der).context("certificate in 'x5c' was not valid DER")
        })
        .collect::<Result<Vec<Certificate>>>()?;

    let Json::String(b64_x509) = x5chain.first().context("'x5c' was an empty array")? else {
        bail!("'x5c' header was not an array of strings");
    };

    let leaf_cert_der = BASE64_STANDARD_NO_PAD
        .decode(b64_x509.trim_end_matches('='))
        .context("leaf certificate in 'x5c' was not valid base64")?;

    let leaf_cert = Certificate::from_der(&leaf_cert_der)
        .context("leaf certificate in 'x5c' was not valid DER")?;

    debug!("Leaf certificate: {leaf_cert:?}");
    Ok((chain, alg))
}

pub fn validate_chain_and_signature<V: Verifier>(
    chain: &[Certificate],
    trusted_roots: Option<&[Certificate]>,
    alg: String,
    request_jwt: String,
) -> Result<()> {
    let leaf_cert = chain.first().context("'x5c' certificate chain was empty")?;

    if let Some(trusted_roots) = trusted_roots {
        let mut chain_refs: Vec<&Certificate> = chain.iter().collect();

        let top = chain.last().expect("chain is non-empty");
        let self_signed = top.tbs_certificate.issuer == top.tbs_certificate.subject;
        let is_ca = top
            .tbs_certificate
            .get::<BasicConstraints>()
            .ok()
            .flatten()
            .map(|(_crit, bc)| bc.ca)
            .unwrap_or(false);

        if self_signed && is_ca {
            // Last certificate is a self-signed CA, so it must be a trusted root to be valid
            if !trusted_roots.iter().any(|root| root == top) {
                bail!("chain's self-signed root is not in the trusted roots list");
            }
        } else {
            // The chain has no root, append the first trusted root that is a valid issuer of the top certificate.
            let root = trusted_roots
                .iter()
                .find(|&root| test_chain_step_validity(top, root).is_empty())
                .context("no trusted root is a valid issuer of the certificate chain")?;
            chain_refs.push(root);
        }

        verify_chain(&chain_refs)?;
    }

    let verifier = V::from_spki(
        leaf_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref(),
        alg,
    )
    .context("unable to parse SPKI")?;

    let (headers_b64, body_b64, sig_b64) = ssi::claims::jws::split_jws(&request_jwt)?;

    let payload = [headers_b64.as_bytes(), b".", body_b64.as_bytes()].concat();
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(sig_b64)
        .context("could not decode base64url encoded jwt signature")?;

    verifier
        .verify(&payload, &signature)
        .context("request signature could not be verified")?;

    Ok(())
}

fn verify_chain(chain: &[&Certificate]) -> Result<()> {
    for window in chain.windows(2) {
        let &[child, parent] = window else { continue };
        let errors = test_chain_step_validity(child, parent);
        if !errors.is_empty() {
            bail!("certificate chain validation failed: {}", errors.join(", "));
        }
    }
    Ok(())
}

pub fn test_chain_step_validity(
    subject: &Certificate,
    candidate_issuer: &Certificate,
) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    if subject.tbs_certificate.issuer != candidate_issuer.tbs_certificate.subject {
        errors.push(String::from("distinguished names do not match"));
    }

    if !signed_using_supported_algorithm(candidate_issuer, subject) {
        errors.push(String::from("issuer did not sign subject"));
    }

    errors
}

fn signed_using_supported_algorithm(candidate_issuer: &Certificate,subject: &Certificate) -> bool {
    match verify_issuer_signature(candidate_issuer, subject) {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!("issuer did not sign subject: {e:#}");
            false
        }
    }
}

fn verify_issuer_signature(candidate_issuer: &Certificate,subject: &Certificate) -> Result<()> {
    let spki = candidate_issuer.tbs_certificate.subject_public_key_info.owned_to_ref();
    let tbs = subject.tbs_certificate.to_der().context("failed to encode subject TBS certificate")?;
    let sig = subject.signature.raw_bytes();
    let oid = subject.signature_algorithm.oid;

    if oid == ECDSA_WITH_SHA_256 {
        let verifier = P256Verifier::from_spki(spki, String::from("ES256"))?;
        let raw = p256::ecdsa::Signature::from_der(sig).context("failed to parse P-256 certificate signature")?.to_bytes();
        verifier.verify(&tbs, raw.as_slice())
    } else if oid == ECDSA_WITH_SHA_384 {
        let verifier = P384Verifier::from_spki(spki, String::from("ES384"))?;
        let raw = p384::ecdsa::Signature::from_der(sig)
            .context("failed to parse P-384 certificate signature")?
            .to_bytes();
        verifier.verify(&tbs, raw.as_slice())
    } else if oid == SHA_256_WITH_RSA_ENCRYPTION {
        RsaVerifier::from_spki(spki, String::from("RS256"))?.verify(&tbs, sig)
    } else if oid == SHA_384_WITH_RSA_ENCRYPTION {
        RsaVerifier::from_spki(spki, String::from("RS384"))?.verify(&tbs, sig)
    } else if oid == SHA_512_WITH_RSA_ENCRYPTION {
        RsaVerifier::from_spki(spki, String::from("RS512"))?.verify(&tbs, sig)
    } else {
        bail!("unsupported certificate signature algorithm: {oid}")
    }

}