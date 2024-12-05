use anyhow::Result;
use openid4vp::verifier::request_signer::P256Signer;
use ssi::claims::jwt::VerifiableCredential;
use ssi::claims::vc::v1::{Context, JsonPresentation};
use ssi::dids::DIDKey;
use ssi::json_ld::iref::UriBuf;
use ssi::prelude::AnyJsonPresentation;
use uuid::Uuid;

pub async fn create_test_verifiable_presentation() -> Result<AnyJsonPresentation> {
    let signer = P256Signer::new(
        p256::SecretKey::from_jwk_str(include_str!("examples/subject.jwk"))
            .unwrap()
            .into(),
    )
    .unwrap();

    let holder_did = DIDKey::generate_url(signer.jwk())?;

    // Create a verifiable presentation using the `examples/vc.jwt` file
    // The signer information is the holder's key, also found in the `examples/subject.jwk` file.
    let verifiable_credential: VerifiableCredential =
        ssi::claims::jwt::decode_unverified(include_str!("examples/vc.jwt"))?;

    let parsed_vc = &verifiable_credential
        .0
        .as_object()
        .expect("Failed to parse credential")
        .get("vc")
        .next()
        .expect("Failed to parse credential")
        .to_owned();

    let mut json_credential = parsed_vc.clone().into_serde_json();

    // NOTE: the `id` in the VC is a UUID string, but it should be a URI
    // according to the `SpecializedJsonCredential` type.
    json_credential.as_object_mut().map(|obj| {
        // Update the ID to be a UriBuf.
        let id = obj
            .get("id")
            .expect("failed to parse vc id")
            .as_str()
            .expect("failed to parse id into string");

        let id_urn = format!("urn:uuid:{id}").as_bytes().to_vec();
        let id_url = UriBuf::new(id_urn).expect("failed to parse id into UriBuf");
        obj.insert("id".to_string(), serde_json::json!(id_url));
    });

    let mut vp = JsonPresentation::default();
    vp.context = Context::default();
    vp.verifiable_credentials
        .push(serde_json::from_value(json_credential)?);
    vp.holder = Some(holder_did.into());
    vp.id = UriBuf::new(
        format!("urn:uuid:{}", Uuid::new_v4())
            .as_bytes()
            .to_vec(),
    )
    .ok();

    Ok(AnyJsonPresentation::V1(vp))
}
