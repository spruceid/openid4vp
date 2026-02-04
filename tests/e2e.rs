use jwt_vp::create_test_verifiable_presentation;
use openid4vp::{
    core::{
        authorization_request::parameters::{ClientMetadata, Nonce, ResponseMode, ResponseType},
        credential_format::*,
        dcql_query::{
            DcqlCredentialClaimsQuery, DcqlCredentialClaimsQueryPath, DcqlCredentialQuery,
            DcqlQuery,
        },
        object::UntypedObject,
        response::{
            parameters::{VpToken, VpTokenItem},
            AuthorizationResponse, UnencodedAuthorizationResponse,
        },
    },
    utils::NonEmptyVec,
    verifier::session::{Outcome, Status},
    wallet::Wallet,
};

mod jwt_vc;
mod jwt_vp;

#[tokio::test]
async fn w3c_vc_did_client_direct_post() {
    let (wallet, verifier) = jwt_vc::wallet_verifier().await;

    // Create a DCQL query for JWT VC credentials
    let mut credential_query =
        DcqlCredentialQuery::new("did-key-id".into(), ClaimFormatDesignation::JwtVcJson);

    // Add claims query for credentialSubject.id
    let claims = NonEmptyVec::new(DcqlCredentialClaimsQuery::new(
        vec![
            DcqlCredentialClaimsQueryPath::String("credentialSubject".into()),
            DcqlCredentialClaimsQueryPath::String("id".into()),
        ]
        .try_into()
        .unwrap(),
    ));
    credential_query.set_claims(Some(claims));

    let dcql_query = DcqlQuery::new(NonEmptyVec::new(credential_query));

    let client_metadata = UntypedObject::default();

    let nonce = Nonce::from("random_nonce");

    let (id, request) = verifier
        .build_authorization_request()
        .with_dcql_query(dcql_query.clone())
        .with_request_parameter(ResponseMode::DirectPost)
        .with_request_parameter(ResponseType::VpToken)
        .with_request_parameter(nonce)
        .with_request_parameter(ClientMetadata(client_metadata))
        .build(wallet.metadata().clone())
        .await
        .unwrap();

    let request = wallet.validate_request(request).await.unwrap();

    // Verify DCQL query is present
    let parsed_dcql = request.dcql_query().unwrap().unwrap();
    assert_eq!(
        dcql_query.credentials().len(),
        parsed_dcql.credentials().len()
    );
    assert_eq!(
        dcql_query.credentials()[0].id(),
        parsed_dcql.credentials()[0].id()
    );

    assert_eq!(&ResponseType::VpToken, request.response_type());
    assert_eq!(&ResponseMode::DirectPost, request.response_mode());

    // The vp_token is a JSON object mapping credential query IDs
    // (from dcql_query) to arrays of Verifiable Presentations.
    let vp = create_test_verifiable_presentation()
        .await
        .expect("failed to create verifiable presentation");

    // Create vp_token with the credential query ID from the DCQL query
    let vp_token = VpToken::with_credential(
        "did-key-id", // This matches the credential query ID in dcql_query
        vec![VpTokenItem::from(vp)],
    );

    let response = AuthorizationResponse::Unencoded(UnencodedAuthorizationResponse::new(vp_token));

    let status = verifier.poll_status(id).await.unwrap();
    assert_eq!(Status::SentRequest, status);

    let redirect = wallet.submit_response(request, response).await.unwrap();

    assert_eq!(None, redirect);

    let status = verifier.poll_status(id).await.unwrap();

    assert!(matches!(status, Status::Complete(Outcome::Success { .. })))
}
