use oid4vp::presentation_exchange::*;

use oid4vp::{
    core::{
        authorization_request::parameters::{ClientMetadata, Nonce, ResponseMode, ResponseType},
        object::UntypedObject,
        response::{parameters::VpToken, AuthorizationResponse, UnencodedAuthorizationResponse},
    },
    presentation_exchange::{PresentationDefinition, PresentationSubmission},
    verifier::session::{Outcome, Status},
    wallet::Wallet,
};
use ssi_jwk::Algorithm;

mod jwt_vc;
mod jwt_vp;

#[tokio::test]
async fn w3c_vc_did_client_direct_post() {
    let (wallet, verifier) = jwt_vc::wallet_verifier().await;

    let presentation_definition = PresentationDefinition::new(
        "did-key-id-proof".into(),
        InputDescriptor::new(
            "did-key-id".into(),
            Constraints::new().add_constraint(
                ConstraintsField::new("$.vp.verifiableCredential.credentialSubject.id".into())
                    .set_name("Verify Identity Key".into())
                    .set_purpose("Check whether your identity key has been verified.".into()),
            ),
        )
        .set_name("DID Key Identity Verification".into())
        .set_purpose("Check whether your identity key has been verified.".into())
        .set_format(ClaimFormat::JwtVc {
            alg: vec![Algorithm::ES256.to_string()],
        }),
    );

    let client_metadata = UntypedObject::default();

    let (id, request) = verifier
        .build_authorization_request()
        .with_presentation_definition(presentation_definition.clone())
        .with_request_parameter(ResponseMode::DirectPost)
        .with_request_parameter(ResponseType::VpToken)
        .with_request_parameter(Nonce::random())
        .with_request_parameter(ClientMetadata(client_metadata))
        .build(wallet.metadata().clone())
        .await
        .unwrap();

    println!("Request: {:?}", request);

    let request = wallet.validate_request(request).await.unwrap();

    let parsed_presentation_definition = request
        .resolve_presentation_definition(wallet.http_client())
        .await
        .unwrap();

    assert_eq!(
        &presentation_definition,
        parsed_presentation_definition.parsed()
    );

    assert_eq!(&ResponseType::VpToken, request.response_type());

    assert_eq!(&ResponseMode::DirectPost, request.response_mode());

    let descriptor_map = parsed_presentation_definition
        .parsed()
        .input_descriptors()
        .iter()
        .map(|descriptor| {
            let format = descriptor
                .format()
                .map(|format| format.designation())
                .to_owned()
                .unwrap_or(ClaimFormatDesignation::JwtVp);

            // NOTE: the input descriptor constraint field path is relative to the path
            // of the descriptor map matching the input descriptor id.
            DescriptorMap::new(descriptor.id().clone(), format, "$".into())
        })
        .collect();

    let presentation_submission = PresentationSubmission::new(
        uuid::Uuid::new_v4(),
        parsed_presentation_definition.parsed().id().clone(),
        descriptor_map,
    );

    let response = AuthorizationResponse::Unencoded(UnencodedAuthorizationResponse(
        Default::default(),
        VpToken(include_str!("examples/vc.jwt").to_owned()),
        presentation_submission.try_into().unwrap(),
    ));

    let status = verifier.poll_status(id).await.unwrap();
    assert_eq!(Status::SentRequest, status);

    let redirect = wallet.submit_response(request, response).await.unwrap();

    assert_eq!(None, redirect);

    let status = verifier.poll_status(id).await.unwrap();
    assert_eq!(Status::Complete(Outcome::Success), status);
}
