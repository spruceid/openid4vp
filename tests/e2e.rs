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
use serde_json::json;

mod jwt_vc;

#[tokio::test]
async fn w3c_vc_did_client_direct_post() {
    let (wallet, verifier) = jwt_vc::wallet_verifier().await;

    // let presentation_definition = PresentationDefinition::new(
    //     uuid::Uuid::new_v4(),
    //     InputDescriptor::new(
    //         uuid::Uuid::new_v4(),
    //         Constraints::new().add_constraint(
    //             ConstraintsField::new(
    //                 "$.vp.verifiableCredential[0].credentialSubject.postalCode".into(),
    //             )
    //             .set_name("Check Postal Code".into())
    //             .set_purpose(String::from(
    //                 "Check whether you live within our school district.",
    //             )),
    //         ),
    //     )
    //     .set_name(String::from("School District Proof"))
    //     .set_purpose(String::from(
    //         "We need to know if you live within our school district.",
    //     ))
    //     .set_format(ClaimFormat::JwtVp {
    //         alg: vec![Algorithm::ES256.to_string()],
    //     }),
    // );

    // Save the presentation definition to a `presentation-exchange/test/presentation-definition/postal-code.json` file.
    // std::fs::write(
    //     "presentation-exchange/test/presentation-definition/postal-code.json",
    //     serde_json::to_string_pretty(&presentation_definition).unwrap(),
    // )
    // .expect("Unable to write file");

    let presentation_definition: PresentationDefinition = serde_json::from_value(json!({
        "id": "0b4dd017-efa6-4a05-a269-9790fa3c22c2",
        "input_descriptors": [
            {
                "id": "064255a8-a0fa-4108-9ded-429f83003350",
                "format": {
                    "jwt_vc_json": {
                        "proof_type": [
                            "JsonWebSignature2020"
                        ]
                    }
                },
                "constraints": {}
            }
        ]
    }))
    .unwrap();

    let client_metadata = UntypedObject::default();

    let (id, request) = verifier
        .build_authorization_request()
        .with_presentation_definition(presentation_definition.clone())
        .with_request_parameter(ResponseMode::DirectPost)
        .with_request_parameter(ResponseType::VpToken)
        .with_request_parameter(Nonce("random123".to_owned()))
        .with_request_parameter(ClientMetadata(client_metadata))
        .build(wallet.metadata().clone())
        .await
        .unwrap();

    println!("Request: {:?}", request);

    let request = wallet.validate_request(request).await.unwrap();

    assert_eq!(
        &presentation_definition,
        request
            .resolve_presentation_definition(wallet.http_client())
            .await
            .unwrap()
            .parsed()
    );

    assert_eq!(&ResponseType::VpToken, request.response_type());

    assert_eq!(&ResponseMode::DirectPost, request.response_mode());

    // TODO: Response with a VP.
    let presentation_submission: PresentationSubmission = serde_json::from_value(json!(
        {
            "id": "39881a17-e454-4d98-87ba-e3073d1014d6",
            "definition_id": "0b4dd017-efa6-4a05-a269-9790fa3c22c2",
            "descriptor_map": [
                {
                    "id": "064255a8-a0fa-4108-9ded-429f83003350",
                    "path": "$",
                    "format": "jwt_vp"
                }
            ]
        }

    ))
    .unwrap();

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
