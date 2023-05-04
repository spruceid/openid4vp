use crate::jar::JwtAuthorizationRequest;
use crate::jar::RequestObject;
use crate::presentation_exchange::InputDescriptor;
use crate::utils::NonEmptyVec;
use isomdl;
use isomdl::definitions::device_request::ItemsRequest;
use isomdl::definitions::device_request::NameSpace;
use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::presentation::device::DeviceSession;
use isomdl::presentation::device::PermittedItems;
use isomdl::presentation::device::oid4vp::RequestedItems;
use isomdl::presentation::device::oid4vp::SessionManager;
use ssi::jwk::JWK;

pub fn prepare_mdoc_response(request: RequestObject, jwk: JWK) {
    //TODO: Get the presentation definition from the request object, or retrieve it through calling http get on the presentation_definition_uri
    // get rid of the unwraps -> use .and_then()

    // TODO: substitute
    let documents = NonEmptyMap::new();
    let permitted_items: super::super::PermittedItems = requested_items.clone();
    let verifier_jwk_str = r#"{
        "use": "sig",
        "kty": "EC",
        "crv": "secp256k1",
        "d": "VTzcE-D-g5EFHcQ-73Qb599qK7X1oAliMu-4WmlnrJ4",
        "x": "HeNB-_4UDuDr8KlR-LGYHhKD3UTCbLWV9XrQg0iHfnQ",
        "y": "64g4jcby5TWR4LogR118SUumQ0TBUiJ-Tl6gMFCEXT0",
        "alg": "ES256K"
    }"#;
    let verifier_jwk: ssi_jwk::JWK = serde_json::from_str(verifier_jwk_str).unwrap();

    if let Some(pres_def) = request.presentation_definition {
        let requested_fields = pres_def
            .input_descriptors
            .first()
            .unwrap()
            .to_owned()
            .constraints
            .unwrap()
            .fields
            .unwrap();

        //TODO: instantiate an isomdl::oid4vp::SessionManager that can prepare the response - BLOCKED BY: refactor oid4vp::SessionManager in isomdl
        // TIP: Check out the respond test in isomdl::presentation::device::oid4vp.rs to understand the full process of responding to a request.
        //let session_manager = isomdl::presentation::device::oid4vp::SessionManager::new()?;
        //let requested_items = session_manager.requested_items();
        //let prepared_response = session_manager.prepare_response(requests, permitted);
        let session_manager = SessionManager::new(
            documents,
            request.aud,
            "nonce".to_string(),
            verifier_jwk,
            request,
        )
        .expect("failed to prepare response");

        let requested_items = session_manager.requested_items();
        let prepared_response = session_manager.prepare_response(requested_items, permitted_items);
    }
}

//TODO: complete the response
// TIP: Check out the respond test in isomdl::presentation::device::oid4vp.rs to understand the full process of responding to a request.
