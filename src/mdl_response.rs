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
use isomdl::presentation::device::RequestedItems;
use isomdl::presentation::device::SessionManager;
use ssi::jwk::JWK;

pub fn prepare_mdoc_response(request: RequestObject, jwk: JWK) {
    //TODO: Get the presentation definition from the request object, or retrieve it through calling http get on the presentation_definition_uri
    // get rid of the unwraps -> use .and_then()
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
    }
}

//TODO: complete the response
// TIP: Check out the respond test in isomdl::presentation::device::oid4vp.rs to understand the full process of responding to a request.
