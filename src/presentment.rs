use crate::mdl_request::ClientMetadata;
use crate::{mdl_request::RequestObject, utils::Openid4vpError};
use async_trait::async_trait;
use isomdl::definitions::helpers::non_empty_map::NonEmptyMap;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl::presentation::device::PreparedDeviceResponse;
use isomdl::presentation::reader::oid4vp::SessionManager;
use serde_json::Value;
use std::collections::BTreeMap;

#[allow(clippy::too_many_arguments)]
pub trait Verify {
    fn mdl_request(
        &self,
        requested_fields: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
        client_id: String,
        redirect_uri: String,
        presentation_id: String,
        response_mode: String,
        client_metadata: ClientMetadata,
        e_reader_key_bytes: String,
    ) -> Result<RequestObject, Openid4vpError>;

    fn validate_mdl_response(
        &self,
        response: &[u8],
    ) -> Result<BTreeMap<String, Value>, Openid4vpError> {
        let device_response: DeviceResponse = serde_cbor::from_slice(response)?;
        let mut session_manager = SessionManager::new(device_response)?;
        Ok(session_manager.handle_response()?)
    }

    //fn vc_request(&self) {}
    //fn validate_vc_response(&self){}
}

#[async_trait]
pub trait Present {
    async fn prepare_mdl_response(
        &self,
        request: RequestObject,
    ) -> Result<PreparedDeviceResponse, Openid4vpError>;
}
