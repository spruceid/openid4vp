use crate::{utils::Error, mdl_request::RequestObject};
use serde_json::Value;
use isomdl::definitions::helpers::NonEmptyMap;
use std::collections::BTreeMap;
use crate::mdl_request::ClientMetadata;
use isomdl;
use isomdl::presentation::device::PreparedDeviceResponse;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl::presentation::reader::oid4vp::SessionManager;


pub trait Verify {
    fn mdl_request(&self, requested_fields: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>> , client_id: String, redirect_uri: String, presentation_id: String, response_mode: String, client_metadata: ClientMetadata) -> Result<RequestObject, Error>;

    fn validate_mdl_response(&self, response: &[u8]) -> Result<BTreeMap<String, Value>, Error> {
        let device_response: DeviceResponse = serde_cbor::from_slice(&response)?;
        let mut session_manager = SessionManager::new(device_response)?;
        Ok(session_manager.handle_response()?)
    }

    //fn vc_request(&self) {}
    //fn validate_vc_response(&self){}
}

pub trait Present {
    fn prepare_mdl_response(&self, request: RequestObject) -> Result<PreparedDeviceResponse, Error>;
}