use anyhow::Error;
use serde::{Deserialize, Serialize};
use url::Url;

use self::parameters::{PresentationSubmission, VpToken};

use super::object::{ParsingErrorContext, UntypedObject};

pub mod parameters;

#[derive(Debug, Clone)]
pub struct AuthorizationResponse(UntypedObject, VpToken, PresentationSubmission);

impl AuthorizationResponse {
    pub fn as_query(self) -> Result<String, Error> {
        Ok(serde_urlencoded::to_string(self.0)?)
    }

    pub fn serializable(self) -> UntypedObject {
        self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostRedirection {
    pub redirect_uri: Url,
}

impl TryFrom<UntypedObject> for AuthorizationResponse {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        let vp_token = value.get().parsing_error()?;
        let presentation_submission = value.get().parsing_error()?;
        Ok(Self(value, vp_token, presentation_submission))
    }
}
