use anyhow::{bail, Context, Result};
use tracing::debug;
use x509_cert::{
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::core::{
    authorization_request::{
        parameters::ClientIdScheme,
        verification::x509::{get_header_certificate, validate_chain_and_signature},
        AuthorizationRequestObject,
    },
    metadata::WalletMetadata,
};

use super::verifier::Verifier;

/// Default implementation of request validation for `x509_san_dns` Client Identifier Prefix.
/// Per OID4VP v1.0 Section 5.9.3.
///  
/// This validates that:
/// 1. The JWT header contains an `x5c` array with at least one certificate
/// 2. The base64url-encoded DNS Subject Alternative Name of the leaf certificate matches the client_id
/// 3. The JWT signature is valid using the leaf certificate's public key
///
/// # Arguments
///
/// * `wallet_metadata` - The wallet's metadata, used to check supported signing algorithms
/// * `request_object` - The decoded authorization request object
/// * `request_jwt` - The original JWT string
/// * `trusted_roots` - Optional trusted root certificates for chain validation - validation is mandatory, this can only be skipped during testing
pub fn validate<V: Verifier>(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_roots: Option<&[Certificate]>,
) -> Result<()> {
    let (chain, alg) = get_header_certificate(wallet_metadata, &request_jwt)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        authorization_request::verification::verifier::P256Verifier, object::UntypedObject,
    };

    use base64::{
        prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
        Engine,
    };

    use crate::core::authorization_request::verification::test_util::*;
    use serde_json::json;
    use x509_cert::der::Encode;

    /// Builds a signed JWT; x5c or alg can be invalid to test error paths
    fn make_jwt(header: serde_json::Value, body: serde_json::Value, key: &SigningKey) -> String {
        let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let b: String = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap());
        let signing_input = format!("{h}.{b}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", BASE64_URL_SAFE_NO_PAD.encode(sig))
    }

    /// Builds header containing specified alg and cert chain
    fn x5c_header(alg: &str, chain: &[&Certificate]) -> serde_json::Value {
        let x5c: Vec<String> = chain
            .iter()
            .map(|c| BASE64_STANDARD.encode(c.to_der().unwrap()))
            .collect();
        json!({ "alg": alg, "x5c": x5c })
    }

    #[test]
    fn validate_x509_san_dns_prefix_success() {
        // Test e2e validation of multi certificate chain with allowed header
        let (chain, key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);

        let jwt = make_jwt(
            x5c_header("ES256", &[&chain[0], &chain.last().unwrap()]),
            json!({
                "client_id": "x509_san_dns:leaf.example",
                "response_type": "vp_token",
                "nonce": "abc123",
                "response_mode": "direct_post",
                "response_uri": "https://example.com/response",
            }),
            &key,
        );
        let authorization_request_object: AuthorizationRequestObject =
            ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
                .unwrap()
                .try_into()
                .unwrap();
        validate::<P256Verifier>(
            &wallet(),
            &authorization_request_object,
            jwt,
            Some(&[chain.last().unwrap().clone()]),
        )
        .unwrap();
    }

    #[test]
    fn dns_san_client_id_mismatch() {
        // Reject request_object has a client_id different from leaf certificate's DNS Subject Alternative Name
        let (chain, key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);

        let jwt = make_jwt(
            x5c_header("ES256", &[&chain[0].clone(), &chain.last().unwrap()]),
            json!({
                "client_id": "x509_san_dns:invalid",
                "response_type": "vp_token",
                "nonce": "abc123",
                "response_mode": "direct_post",
                "response_uri": "https://example.com/response",
            }),
            &key,
        );
        let authorization_request_object: AuthorizationRequestObject =
            ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
                .unwrap()
                .try_into()
                .unwrap();
        assert!(validate::<P256Verifier>(
            &wallet(),
            &authorization_request_object,
            jwt,
            Some(&[chain.last().unwrap().clone()])
        )
        .unwrap_err()
        .to_string()
        .contains("client_id does not match any DNS Subject Alternative Name"));
    }

    #[test]
    fn no_client_id() {
        // Reject request_object that doesn't contain client_id
        let (chain, key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);

        let jwt = make_jwt(
            x5c_header("ES256", &[&chain[0], &chain.last().unwrap()]),
            json!({
                "response_type": "vp_token",
                "nonce": "abc123",
                "response_mode": "direct_post",
                "response_uri": "https://example.com/response",
            }),
            &key,
        );
        let authorization_request_object: AuthorizationRequestObject =
            ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
                .unwrap()
                .try_into()
                .unwrap();
        assert!(validate::<P256Verifier>(
            &wallet(),
            &authorization_request_object,
            jwt,
            Some(&[chain.last().unwrap().clone()])
        )
        .unwrap_err()
        .to_string()
        .contains("client_id is required"));
    }

    #[test]
    fn reject_untrusted_root_x509_san() {
        // Test e2e validation of multi certificate chain containing untrusted root
        let (chain, key) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);

        let (unrelated_chain, _) = issued_chain(&[
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ]);

        let jwt = make_jwt(
            x5c_header("ES256", &[&chain[0], &chain.last().unwrap()]),
            json!({
                "client_id": "x509_san_dns:leaf.example",
                "response_type": "vp_token",
                "nonce": "abc123",
                "response_mode": "direct_post",
                "response_uri": "https://example.com/response",
            }),
            &key,
        );
        let authorization_request_object: AuthorizationRequestObject =
            ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
                .unwrap()
                .try_into()
                .unwrap();
        assert!(validate::<P256Verifier>(
            &wallet(),
            &authorization_request_object,
            jwt,
            Some(&[unrelated_chain.last().unwrap().clone()]),
        )
        .unwrap_err()
        .to_string()
        .contains("chain's self-signed root is not in the trusted roots list"));
    }
}
