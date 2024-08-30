use std::str::FromStr;

use anyhow::Result;
use oid4vp::core::response::parameters::VpToken;
use oid4vp::holder::verifiable_presentation_builder::{
    VerifiablePresentationBuilder, VerifiablePresentationBuilderOptions,
};
use oid4vp::verifier::request_signer::P256Signer;
use ssi_claims::jwt;
use ssi_dids::DIDKey;
use ssi_jwk::JWK;

pub async fn create_test_verifiable_presentation_token() -> Result<VpToken> {
    let verifier = JWK::from_str(include_str!("examples/verifier.jwk"))?;

    let signer = P256Signer::new(
        p256::SecretKey::from_jwk_str(include_str!("examples/subject.jwk"))
            .unwrap()
            .into(),
    )
    .unwrap();

    let holder_did = DIDKey::generate_url(signer.jwk())?;
    let verifier_did = DIDKey::generate_url(&verifier)?;

    // Create a verifiable presentation using the `examples/vc.jwt` file
    // The signer information is the holder's key, also found in the `examples/subject.jwk` file.
    let verifiable_credential: jwt::VerifiableCredential =
        ssi_claims::jwt::decode_unverified(include_str!("examples/vc.jwt"))?;

    let verifiable_presentation =
        VerifiablePresentationBuilder::from_options(VerifiablePresentationBuilderOptions {
            issuer: holder_did.clone(),
            subject: holder_did.clone(),
            audience: verifier_did.clone(),
            expiration_secs: 3600,
            credentials: vec![verifiable_credential.0].into(),
            nonce: "random_nonce".into(),
        });

    let token = verifiable_presentation.as_base64_encoded_vp_token()?;

    Ok(token)
}
