use jwt_vp::create_test_verifiable_presentation_token;
use oid4vp::{
    core::{
        authorization_request::parameters::{ClientMetadata, Nonce, ResponseMode, ResponseType},
        credential_format::*,
        input_descriptor::*,
        object::UntypedObject,
        presentation_definition::*,
        presentation_submission::*,
        response::{AuthorizationResponse, UnencodedAuthorizationResponse},
    },
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
            Constraints::new()
                .add_constraint(
                    // Add a constraint fields to check if the credential
                    // conforms to a specific path.
                    ConstraintsField::new("$.credentialSubject.id".into())
                        // Add alternative path(s) to check multiple potential formats.
                        .add_path("$.vp.verifiableCredential.vc.credentialSubject.id".into())
                        .add_path("$.vp.verifiableCredential[0].vc.credentialSubject.id".into())
                        .set_name("Verify Identity Key".into())
                        .set_purpose("Check whether your identity key has been verified.".into())
                        .set_filter(serde_json::json!({
                            "type": "string",
                            "pattern": "did:key:.*"
                        }))
                        .set_predicate(Predicate::Required),
                )
                .set_limit_disclosure(ConstraintsLimitDisclosure::Required),
        )
        .set_name("DID Key Identity Verification".into())
        .set_purpose("Check whether your identity key has been verified.".into())
        .set_format((|| {
            let mut map = ClaimFormatMap::new();
            map.insert(
                ClaimFormatDesignation::JwtVcJson,
                ClaimFormatPayload::Alg(vec![Algorithm::ES256.to_string()]),
            );
            map
        })()),
    );

    let client_metadata = UntypedObject::default();

    let nonce = Nonce::from("random_nonce");

    let (id, request) = verifier
        .build_authorization_request()
        .with_presentation_definition(presentation_definition.clone())
        .with_request_parameter(ResponseMode::DirectPost)
        .with_request_parameter(ResponseType::VpToken)
        .with_request_parameter(nonce)
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
        presentation_definition.id(),
        parsed_presentation_definition.parsed().id()
    );

    assert_eq!(&ResponseType::VpToken, request.response_type());

    assert_eq!(&ResponseMode::DirectPost, request.response_mode());

    let descriptor_map = parsed_presentation_definition
        .parsed()
        .input_descriptors()
        .iter()
        .map(|descriptor| {
            // NOTE: the input descriptor constraint field path is relative to the path
            // of the descriptor map matching the input descriptor id.
            DescriptorMap::new(
                descriptor.id().to_string(),
                // NOTE: Since the input descriptor may support several different
                // claim format types. This value should not be hardcoded in production
                // code, but should be selected from available formats in the presentation definition
                // input descriptor.
                //
                // In practice, this format will be determined by the VDC collection's credential format.
                ClaimFormatDesignation::JwtVpJson,
                // Starts at the top level path of the verifiable submission, which contains a `vp` key
                // for verifiable presentations, which include the verifiable credentials under the `verifiableCredentials`
                // field.
                "$".into(),
            )
            .set_path_nested(DescriptorMap::new(
                // Descriptor map id must be the same as the parent descriptor map id.
                descriptor.id().to_string(),
                ClaimFormatDesignation::JwtVcJson,
                // This nested path is relative to the resolved path of the parent descriptor map.
                // In this case, the parent descriptor map resolved to the `vp` key.
                // The nested path is relative to the `vp` key.
                //
                // See: https://identity.foundation/presentation-exchange/spec/v2.0.0/#processing-of-submission-entries
                "$.vp.verifiableCredential[0]".into(),
            ))
        })
        .collect();

    let presentation_submission = PresentationSubmission::new(
        uuid::Uuid::new_v4(),
        parsed_presentation_definition.parsed().id().clone(),
        descriptor_map,
    );

    let token = create_test_verifiable_presentation_token()
        .await
        .expect("Failed to create token");

    let response = AuthorizationResponse::Unencoded(UnencodedAuthorizationResponse(
        Default::default(),
        token,
        presentation_submission.try_into().unwrap(),
    ));

    let status = verifier.poll_status(id).await.unwrap();
    assert_eq!(Status::SentRequest, status);

    let redirect = wallet.submit_response(request, response).await.unwrap();

    assert_eq!(None, redirect);

    let status = verifier.poll_status(id).await.unwrap();

    println!("Status: {:?}", status);

    assert!(matches!(status, Status::Complete(Outcome::Success { .. })))
}
