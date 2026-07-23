use anyhow::{bail, Context, Result};
use base64::prelude::*;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use serde_json::{Map, Value as Json};
use time::OffsetDateTime;
use tracing::debug;
use x509_cert::{
    der::{referenced::OwnedToRef, Decode, Encode},
    ext::pkix::{BasicConstraints, KeyUsage},
    Certificate,
};

use crate::core::{
    metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
    object::ParsingErrorContext,
};

use super::verifier::{P256Verifier, P384Verifier, RsaVerifier, Verifier};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum X509VerificationError {
    #[error("distinguished names do not match")]
    DnMismatch,
    #[error("issuer did not sign subject")]
    IssuerSignatureInvalid,
    #[error("issuing certificate is not a CA")]
    IssuerNotCa,
    #[error(
        "non-self-issued intermediate certificates that follow this certificate exceed constraint"
    )]
    ExceedPathLenConstraint,
    #[error("issuing certificate's public key is not authorized to sign")]
    IssuerNotAuthorizedToSign,
    #[error("certificate is expired")]
    Expired,
    #[error("certificate is not yet valid")]
    NotYetValid,
    #[error("chain's self-signed root is not in the trusted roots list")]
    UntrustedRoot,
    #[error("leaf certificate is not authorized to sign (missing digitalSignature key usage)")]
    LeafNotAuthorizedToSign,
    #[error("no trusted root is a valid issuer of the certificate chain")]
    NoValidTrustedRoot,
    #[error("request signature could not be verified")]
    SignatureVerificationFailed,
    #[error("{reason}")]
    BadRequest { reason: String },
}

/// Shared functionality from x509_san.rs and x509_hash.rs to check whether the JWT header contains an `x5c` array and valid `alg`
/// Validates and decodes certificate chain
pub fn get_header_certificate(
    wallet_metadata: &WalletMetadata,
    request_jwt: &str,
) -> Result<(Vec<Certificate>, String)> {
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

/// Ensure certificate chain is anchored with trusted root and each certificate signature is valid
pub fn validate_chain_and_signature<V: Verifier>(
    chain: &[Certificate],
    trusted_roots: Option<&[Certificate]>,
    alg: String,
    request_jwt: String,
) -> Result<(), X509VerificationError> {
    let leaf_cert = chain.first().ok_or(X509VerificationError::BadRequest {
        reason: ("'x5c' certificate chain was empty".to_string()),
    })?;

    if let Some(trusted_roots) = trusted_roots.filter(|roots| !roots.is_empty()) {
        let mut chain_refs: Vec<&Certificate> = chain.iter().collect();
        // Check if last provided certificate is a root
        let top = chain.last().expect("chain is non-empty");
        let self_signed = top.tbs_certificate.issuer == top.tbs_certificate.subject;
        let is_ca = is_ca(top);

        if self_signed && is_ca {
            // Last certificate is a self-signed CA, so it must be a trusted root to be valid
            if !trusted_roots.iter().any(|root| root == top) {
                return Err(X509VerificationError::UntrustedRoot);
            }
        } else {
            // The chain has no root, append the first trusted root that is a valid issuer of the top certificate.
            let root = trusted_roots
                .iter()
                .find(|&root| validate_chain_steps(top, root).is_ok())
                .ok_or(X509VerificationError::NoValidTrustedRoot)?;
            chain_refs.push(root);
        }

        validate_full_chain(&chain_refs)?;
    }

    // A leaf certificate should have the digitalSignature bit asserted (RFC 5280 §4.2.1.3) in order to verify request object signatures
    if let Some((_crit, ku)) = leaf_cert.tbs_certificate.get::<KeyUsage>().ok().flatten() {
        if !ku.digital_signature() {
            return Err(X509VerificationError::LeafNotAuthorizedToSign);
        }
    }

    let verifier = V::from_spki(
        leaf_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref(),
        alg,
    )
    .map_err(|_| X509VerificationError::BadRequest {
        reason: ("unable to parse SPKI".to_string()),
    })?;

    let (headers_b64, body_b64, sig_b64) =
        ssi::claims::jws::split_jws(&request_jwt).map_err(|_| {
            X509VerificationError::BadRequest {
                reason: ("request object jwt was malformed".to_string()),
            }
        })?;

    let payload = [headers_b64.as_bytes(), b".", body_b64.as_bytes()].concat();
    let signature =
        BASE64_URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| X509VerificationError::BadRequest {
                reason: ("could not decode base64url encoded jwt signature".to_string()),
            })?;

    verifier
        .verify(&payload, &signature)
        .map_err(|_| X509VerificationError::SignatureVerificationFailed)?;

    Ok(())
}

/// Split certificate chain into pairs to check signature validity
fn validate_full_chain(chain: &[&Certificate]) -> Result<(), X509VerificationError> {
    if chain.is_empty() {
        return Err(X509VerificationError::BadRequest {
            reason: ("'x5c' certificate chain was empty".to_string()),
        });
    }
    // check leaf cert's validity period, issuers are checked in validate_chain_steps
    check_cert_validity_period(chain[0])?;

    // pathLenConstraint counts only non-self-issued intermediates (RFC 5280 §4.2.1.9).
    let mut non_self_issued_below = 0;
    for (position, window) in chain.windows(2).enumerate() {
        let &[child, parent] = window else { continue };

        if position > 0 && !is_self_issued(child) {
            non_self_issued_below += 1
        }
        validate_chain_steps(child, parent)?;

        if let Some(max_path_len) = path_len(parent) {
            if non_self_issued_below > usize::from(max_path_len) {
                return Err(X509VerificationError::ExceedPathLenConstraint);
            }
        }
    }
    Ok(())
}

/// RFC 5280 §3.2: Self-issued certificates are CA certificates in which the issuer and subject are the same entity.
fn is_self_issued(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

fn is_ca(cert: &Certificate) -> bool {
    cert.tbs_certificate
        .get::<BasicConstraints>()
        .ok()
        .flatten()
        .map(|(_crit, bc)| bc.ca)
        .unwrap_or(false)
}

fn path_len(cert: &Certificate) -> Option<u8> {
    cert.tbs_certificate
        .get::<BasicConstraints>()
        .ok()
        .flatten()
        .and_then(|(_crit, bc)| bc.path_len_constraint)
}

fn key_cert_sign(cert: &Certificate) -> bool {
    cert.tbs_certificate
        .get::<KeyUsage>()
        .ok()
        .flatten()
        .map(|(_crit, bc)| bc.key_cert_sign())
        .unwrap_or(false)
}

fn validate_chain_steps(
    subject: &Certificate,
    candidate_issuer: &Certificate,
) -> Result<(), X509VerificationError> {
    if subject.tbs_certificate.issuer != candidate_issuer.tbs_certificate.subject {
        return Err(X509VerificationError::DnMismatch);
    } else if !signed_using_supported_algorithm(candidate_issuer, subject) {
        return Err(X509VerificationError::IssuerSignatureInvalid);
    }

    if !is_ca(candidate_issuer) {
        return Err(X509VerificationError::IssuerNotCa);
    }
    if !key_cert_sign(candidate_issuer) {
        return Err(X509VerificationError::IssuerNotAuthorizedToSign);
    }
    // leaf validity was tested previously, verify intermediates + root
    check_cert_validity_period(candidate_issuer)?;

    Ok(())
}

fn check_cert_validity_period(certificate: &Certificate) -> Result<(), X509VerificationError> {
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    let validity = certificate.tbs_certificate.validity;
    if validity.not_after.to_unix_duration().as_secs() < now {
        return Err(X509VerificationError::Expired);
    };
    if validity.not_before.to_unix_duration().as_secs() > now {
        return Err(X509VerificationError::NotYetValid);
    };
    Ok(())
}

fn signed_using_supported_algorithm(candidate_issuer: &Certificate, subject: &Certificate) -> bool {
    match verify_issuer_signature(candidate_issuer, subject) {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!("issuer did not sign subject: {e:#}");
            false
        }
    }
}

fn verify_issuer_signature(candidate_issuer: &Certificate, subject: &Certificate) -> Result<()> {
    let spki = candidate_issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let tbs = subject
        .tbs_certificate
        .to_der()
        .context("failed to encode subject TBS certificate")?;
    let sig = subject.signature.raw_bytes();
    let oid = subject.signature_algorithm.oid;

    if oid == ECDSA_WITH_SHA_256 {
        let verifier = P256Verifier::from_spki(spki, String::from("ES256"))?;
        let raw = p256::ecdsa::Signature::from_der(sig)
            .context("failed to parse P-256 certificate signature")?
            .to_bytes();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::authorization_request::verification::test_util::*;
    use rcgen::{
        DistinguishedName,
        KeyUsagePurpose::{DigitalSignature, KeyCertSign, KeyEncipherment},
        SignatureAlgorithm,
    };
    use serde_json::json;

    struct Leaf {
        cert: Certificate,
        key: SigningKey,
    }

    /// Self-signed P-256 CA cert + its signing key
    fn self_signed_cert(alg: &'static SignatureAlgorithm, common_name: &str) -> Leaf {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let key_pair = KeyPair::generate_for(alg).unwrap();
        let mut params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyCertSign, DigitalSignature];
        let cert = params.self_signed(&key_pair).unwrap();

        let key = SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        Leaf {
            cert: to_x509(&cert),
            key,
        }
    }

    #[test]
    fn decode_multi_cert_chain() {
        // Test get_header_certificate ability to decode multi certificate chain and extract alg from header
        let (chain, key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);

        let jwt = make_jwt(
            x5c_header(
                "ES256",
                &[&chain[0].clone(), &chain.last().unwrap().clone()],
            ),
            &key,
        );

        let (chain, alg) = get_header_certificate(&wallet(), &jwt).unwrap();
        assert_eq!(alg, "ES256");
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn header_missing_alg() {
        let leaf = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "leaf");
        let jwt = make_jwt(json!({ "x5c": [] }), &leaf.key);
        let err = get_header_certificate(&wallet(), &jwt).unwrap_err();
        assert!(err.to_string().contains("'alg' was missing"));
    }

    #[test]
    fn header_rejects_unsupported_alg() {
        let leaf = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "leaf");
        let jwt = make_jwt(x5c_header("ES384", &[&leaf.cert]), &leaf.key);
        assert!(get_header_certificate(&wallet(), &jwt)
            .unwrap_err()
            .to_string()
            .contains("unsupported algorithm"));
    }

    #[test]
    fn header_missing_x5c() {
        let leaf = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "leaf");
        let jwt = make_jwt(json!({ "alg": "ES256" }), &leaf.key);
        assert!(get_header_certificate(&wallet(), &jwt)
            .unwrap_err()
            .to_string()
            .contains("'x5c' was missing"));
    }

    #[test]
    fn header_rejects_empty_x5c() {
        let leaf = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "leaf");
        let jwt = make_jwt(json!({ "alg": "ES256", "x5c": [] }), &leaf.key);
        assert!(get_header_certificate(&wallet(), &jwt)
            .unwrap_err()
            .to_string()
            .contains("empty array"));
    }

    #[test]
    fn no_trusted_roots_success_es256() {
        // Test if signature validation completes without trusted roots provided (None)
        let leaf = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "leaf");
        let jwt = make_jwt(x5c_header("ES256", &[&leaf.cert]), &leaf.key);
        validate_chain_and_signature::<P256Verifier>(
            &[leaf.cert.clone()],
            None,
            "ES256".into(),
            jwt,
        )
        .unwrap();
    }

    #[test]
    fn no_trusted_roots_success_es384() {
        // Test if signature validation completes without trusted roots provided (empty slice)
        let leaf = self_signed_cert(&rcgen::PKCS_ECDSA_P384_SHA384, "leaf");
        let jwt = make_jwt(x5c_header("ES384", &[&leaf.cert]), &leaf.key);
        validate_chain_and_signature::<P384Verifier>(
            &[leaf.cert.clone()],
            Some(&[]),
            "ES384".into(),
            jwt,
        )
        .unwrap();
    }

    #[test]
    // JWT signature is signed by the wrong key (not leaf certificate's key)
    fn invalid_jwt_signature() {
        let leaf = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "cert");
        let other = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "cert");
        let jwt = make_jwt(x5c_header("ES256", &[&leaf.cert]), &other.key);
        assert!(validate_chain_and_signature::<P256Verifier>(
            &[leaf.cert.clone()],
            None,
            "ES256".into(),
            jwt,
        )
        .is_err());
    }

    #[test]
    fn empty_chain_is_rejected() {
        assert!(validate_chain_and_signature::<P256Verifier>(
            &[],
            None,
            "ES256".into(),
            "a.b.c".into(),
        )
        .unwrap_err()
        .to_string()
        .contains("chain was empty"));
    }

    #[test]
    // x5c carries only the leaf; the issuing root lives in trusted_roots
    fn accepts_chain_when_root_appended_from_trusted_roots() {
        let (chain, key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
        ]);
        let jwt = make_jwt(x5c_header("ES384", &[&chain[0].clone()]), &key);
        validate_chain_and_signature::<P384Verifier>(
            &[chain[0].clone(), chain[1].clone()],
            Some(&[chain.last().unwrap().clone()]),
            "ES384".into(),
            jwt,
        )
        .unwrap();
    }

    #[test]
    // Root on x5c is not included in trusted roots
    fn rejects_with_untrusted_root() {
        let (chain, key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);
        let trusted_root_1 = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "trusted_root_1");
        let trusted_root_2 = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "trusted_root_2");
        let jwt = make_jwt(x5c_header("ES256", &[&chain[0].clone()]), &key);

        let formatted_chain = [chain[0].clone(), chain[1].clone()];
        let formatted_trusted_roots = [trusted_root_1.cert, trusted_root_2.cert];
        assert!(validate_chain_and_signature::<P256Verifier>(
            &formatted_chain,
            Some(&formatted_trusted_roots),
            "ES256".into(),
            jwt,
        )
        .unwrap_err()
        .to_string()
        .contains("root is not in the trusted roots list"));
    }

    #[test]
    // Root is trusted, but leaf certificate signs intermediate cert
    fn rejects_with_leaf_as_issuer() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(vec!["root.example".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyCertSign];
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        leaf_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        leaf_params.key_usages = vec![KeyCertSign];
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let inter_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params = CertificateParams::new(vec!["inter.example".into()]).unwrap();
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_params.key_usages = vec![KeyCertSign];
        let inter_cert = inter_params
            .signed_by(&inter_key, &leaf_cert, &leaf_key)
            .unwrap();

        let key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let x509_chain = [
            &to_x509(&leaf_cert),
            &to_x509(&inter_cert),
            &to_x509(&root_cert),
        ];

        let jwt = make_jwt(x5c_header("ES256", &x509_chain), &key);

        let err = validate_chain_and_signature::<P256Verifier>(
            &[
                x509_chain[0].clone(),
                x509_chain[1].clone(),
                x509_chain[2].clone(),
            ],
            Some(&[to_x509(&root_cert)]),
            "ES256".into(),
            jwt,
        )
        .unwrap_err();
        assert_eq!(err, X509VerificationError::IssuerSignatureInvalid,);
    }

    #[test]
    // Include postdated leaf - should fail early
    fn postdated_leaf() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use time::Duration;

        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(vec!["root.example".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyCertSign];
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();

        // Valid 10 days from now
        let now = OffsetDateTime::now_utc();
        leaf_params.not_before = now + Duration::days(10);
        leaf_params.not_after = now + Duration::days(375);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let x509_chain = [&to_x509(&leaf_cert), &to_x509(&root_cert)];

        let jwt = make_jwt(x5c_header("ES256", &x509_chain), &key);

        let err = validate_chain_and_signature::<P256Verifier>(
            &[x509_chain[0].clone(), x509_chain[1].clone()],
            Some(&[to_x509(&root_cert)]),
            "ES256".into(),
            jwt,
        )
        .unwrap_err();
        assert_eq!(err, X509VerificationError::NotYetValid,);
    }

    #[test]
    // Include expired certificate in chain
    fn expired_cert() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use time::Duration;

        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(vec!["root.example".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyCertSign];
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let inter_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params = CertificateParams::new(vec!["inter.example".into()]).unwrap();
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_params.key_usages = vec![KeyCertSign];
        // Expired yesterday
        let now = OffsetDateTime::now_utc();
        inter_params.not_before = now - Duration::days(10);
        inter_params.not_after = now - Duration::days(1);
        let inter_cert = inter_params
            .signed_by(&inter_key, &root_cert, &root_key)
            .unwrap();

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_cert, &inter_key)
            .unwrap();

        let key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let x509_chain = [
            &to_x509(&leaf_cert),
            &to_x509(&inter_cert),
            &to_x509(&root_cert),
        ];

        let jwt = make_jwt(x5c_header("ES256", &x509_chain), &key);

        let err = validate_chain_and_signature::<P256Verifier>(
            &[
                x509_chain[0].clone(),
                x509_chain[1].clone(),
                x509_chain[2].clone(),
            ],
            Some(&[to_x509(&root_cert)]),
            "ES256".into(),
            jwt,
        )
        .unwrap_err();

        assert_eq!(err, X509VerificationError::Expired,);
    }

    #[test]
    // Reject leaf that doesn't assert digitalSignature bit in KeyUsage extension
    fn reject_leaf_without_digital_signature_bit() {
        use rcgen::{CertificateParams, KeyPair};
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        leaf_params.key_usages = vec![KeyEncipherment]; // indicates the key should only be used for key management
        let leaf_cert = leaf_params.self_signed(&leaf_key).unwrap();
        let key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let x509_chain = [&to_x509(&leaf_cert)];

        let jwt = make_jwt(x5c_header("ES384", &x509_chain), &key);
        let err = validate_chain_and_signature::<P384Verifier>(
            &[x509_chain[0].clone()],
            Some(&[]),
            "ES384".into(),
            jwt,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("is not authorized"))
    }

    #[test]
    // Test valid signature between pair of certificates (root and leaf)
    fn step_issuer_subject_success() {
        let (chain, _key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);
        assert!(validate_chain_steps(&chain[0], &chain.last().unwrap()).is_ok());
    }

    #[test]
    // Reject distinguished names not matching in pair of two self signed certificates
    fn reject_dn_mismatch() {
        let cert1 = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "cert1").cert;
        let cert2 = self_signed_cert(&rcgen::PKCS_ECDSA_P256_SHA256, "cert2").cert;
        assert_eq!(
            validate_chain_steps(&cert1, &cert2).unwrap_err(),
            X509VerificationError::DnMismatch
        )
    }

    #[test]
    // Reject when an unrelated cert is not the signer of leaf
    fn reject_broken_signature() {
        let (chain, _key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);
        let (unrelated_chain, _) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);
        assert_eq!(
            validate_chain_steps(&chain[0], &unrelated_chain.last().unwrap()).unwrap_err(),
            X509VerificationError::IssuerSignatureInvalid
        )
    }

    #[test]
    // Reject issuers that are not CA
    fn reject_not_ca() {
        use rcgen::{CertificateParams, KeyPair};

        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(vec!["root.example".into()]).unwrap();
        root_params.key_usages = vec![KeyCertSign];
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();
        assert_eq!(
            validate_chain_steps(&to_x509(&leaf_cert), &to_x509(&root_cert)).unwrap_err(),
            X509VerificationError::IssuerNotCa
        );
    }

    #[test]
    // Reject chains that exceed a CA's pathLenConstraint
    fn reject_exceed_pathlen() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        // A distinct subject distinguished name is used for each certificate so they can be formed as non-self-issued, hence counting towards the path length constraint
        fn ca_params(cn: &str, constraint: BasicConstraints) -> CertificateParams {
            let mut params = CertificateParams::new(vec![format!("{cn}.example")]).unwrap();
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(DnType::CommonName, cn);
            params.distinguished_name = dn;
            params.is_ca = IsCa::Ca(constraint);
            params.key_usages = vec![KeyCertSign];
            params
        }

        // chain is leaf > inter_2 > inter_1 > root; inter_1 has pathLen=0
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let root_cert = ca_params("root", BasicConstraints::Unconstrained)
            .self_signed(&root_key)
            .unwrap();

        let inter_1_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let inter_1_cert = ca_params("inter_1", BasicConstraints::Constrained(0))
            .signed_by(&inter_1_key, &root_cert, &root_key)
            .unwrap();

        let inter_2_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let inter_2_cert = ca_params("inter_2", BasicConstraints::Unconstrained)
            .signed_by(&inter_2_key, &inter_1_cert, &inter_1_key)
            .unwrap();

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        let mut leaf_dn = rcgen::DistinguishedName::new();
        leaf_dn.push(DnType::CommonName, "leaf");
        leaf_params.distinguished_name = leaf_dn;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_2_cert, &inter_2_key)
            .unwrap();

        let chain = [
            &to_x509(&leaf_cert),
            &to_x509(&inter_2_cert),
            &to_x509(&inter_1_cert),
            &to_x509(&root_cert),
        ];
        assert_eq!(
            validate_full_chain(&chain).unwrap_err(),
            X509VerificationError::ExceedPathLenConstraint
        );
    }

    #[test]
    // Reject issuers that are not authorized to sign other certificates
    fn reject_not_authorized_to_sign() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(vec!["root.example".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_params = CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        assert_eq!(
            validate_chain_steps(&to_x509(&leaf_cert), &to_x509(&root_cert)).unwrap_err(),
            X509VerificationError::IssuerNotAuthorizedToSign
        )
    }
}
