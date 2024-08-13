use std::sync::Arc;

use anyhow::Result;

use oid4vp::verifier::request_signer::{P256Signer, RequestSigner};
use ssi_claims::jwt::{AnyRegisteredClaim, RegisteredClaim};
use ssi_claims::{
    jwt::{Subject, VerifiableCredential},
    vc::v1::VerifiablePresentation,
    ResourceProvider,
};
use ssi_dids::{DIDKey, DIDJWK};
use ssi_jwk::JWK;

#[tokio::test]
async fn test_verifiable_presentation() -> Result<()> {
    // // Create a holder DID and key
    // let mut holder_key = JWK::generate_p256();
    // let holder_did = DIDJWK::generate_url(&holder_key.to_public());

    // holder_key.key_id = Some(holder_did.into());

    let signer = Arc::new(
        P256Signer::new(
            p256::SecretKey::from_jwk_str(include_str!("examples/subject.jwk"))
                .unwrap()
                .into(),
        )
        .unwrap(),
    );

    println!("Signer: {:?}", signer.jwk());

    let holder_did = DIDKey::generate_url(&signer.jwk())?;

    // Create a verifiable presentation using the `examples/vc.jwt` file
    // The signer information is the holder's key, also found in the `examples/subject.jwk` file.
    let verifiable_credential: VerifiableCredential =
        ssi_claims::jwt::decode_unverified(include_str!("examples/vc.jwt"))?;

    let subject = Subject::extract(AnyRegisteredClaim::from(verifiable_credential.clone()));

    // assert_eq!(holder_did.as_did_url(), subject);

    println!("VC: {:?}", verifiable_credential);

    println!("Holder DID: {:?}", holder_did);

    println!("Subject: {:?}", subject);

    Ok(())
}
