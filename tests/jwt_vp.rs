use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use oid4vp::core::authorization_request::parameters::Nonce;
use oid4vp::verifier::request_signer::{P256Signer, RequestSigner};
use ssi_claims::jwt::VerifiablePresentation;
use ssi_claims::vc::v2::syntax::VERIFIABLE_PRESENTATION_TYPE;
use ssi_claims::{CompactJWSString, JWSPayload, JWTClaims};
// use ssi_claims::vc::v1::VerifiableCredential;
use ssi_claims::jwt;
use ssi_dids::ssi_json_ld::syntax::{Object, Value};
use ssi_dids::ssi_json_ld::CREDENTIALS_V1_CONTEXT;
use ssi_dids::DIDKey;
use ssi_jwk::JWK;

pub async fn create_test_verifiable_presentation() -> Result<CompactJWSString> {
    let verifier = JWK::from_str(include_str!("examples/verifier.jwk"))?;

    let signer = Arc::new(
        P256Signer::new(
            p256::SecretKey::from_jwk_str(include_str!("examples/subject.jwk"))
                .unwrap()
                .into(),
        )
        .unwrap(),
    );

    println!("Signer: {:?}", signer.jwk());

    let holder_jwk = JWK::from_str(std::include_str!("examples/subject.jwk"))?;
    let holder_did = DIDKey::generate_url(&signer.jwk())?;

    let verifier_did = DIDKey::generate_url(&verifier)?;

    // Create a verifiable presentation using the `examples/vc.jwt` file
    // The signer information is the holder's key, also found in the `examples/subject.jwk` file.
    let verifiable_credential: jwt::VerifiableCredential =
        ssi_claims::jwt::decode_unverified(include_str!("examples/vc.jwt"))?;

    println!("VC: {:?}", verifiable_credential);

    // TODO: There should be a more idiomatically correct way to do this, if not already implemented.
    // NOTE: There is an unused `VerifiablePresentationBuilder` in the holder module, however, these methods
    // may best be implemented as methods on the `VerifiablePresentation` struct itself.
    let mut verifiable_presentation = VerifiablePresentation(Value::Object(Object::new()));

    verifiable_presentation.0.as_object_mut().map(|obj| {
        // The issuer is the holder of the verifiable credential (subject of the verifiable credential).
        obj.insert("iss".into(), Value::String(holder_did.as_str().into()));

        // The audience is the verifier of the verifiable credential.
        obj.insert("aud".into(), Value::String(verifier_did.as_str().into()));

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|dur| {
                // The issuance date is the current time.
                obj.insert("iat".into(), Value::Number(dur.as_secs().into()));

                // The expiration date is 1 hour from the current time.
                obj.insert("exp".into(), Value::Number((dur.as_secs() + 3600).into()));
            });

        obj.insert(
            "nonce".into(),
            Value::String(Nonce::from("random_nonce").to_string().into()),
        );

        let mut verifiable_credential_field = Value::Object(Object::new());

        verifiable_credential_field.as_object_mut().map(|cred| {
            cred.insert(
                "@context".into(),
                Value::String(CREDENTIALS_V1_CONTEXT.to_string().into()),
            );

            cred.insert(
                "type".into(),
                Value::String(VERIFIABLE_PRESENTATION_TYPE.to_string().into()),
            );

            cred.insert(
                "verifiableCredential".into(),
                Value::Array(vec![verifiable_credential.0]),
            );
        });

        obj.insert("vp".into(), verifiable_credential_field);
    });

    let claim = JWTClaims::from_private_claims(verifiable_presentation);

    let jwt = claim
        .sign(&holder_jwk)
        .await
        .expect("Failed to sign Verifiable Presentation JWT");

    println!("JWT: {:?}", jwt);

    let vp: jwt::VerifiablePresentation = ssi_claims::jwt::decode_unverified(jwt.as_str())?;

    println!("VP: {:?}", vp);

    Ok(jwt)
}
