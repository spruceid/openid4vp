pub use crate::core::authorization_request::parameters::State;
use crate::core::object::TypedParameter;
use crate::core::presentation_definition::PresentationDefinition;
use crate::core::presentation_submission::{
    DescriptorMap, PresentationSubmission as PresentationSubmissionParsed,
};

use anyhow::Error;
use base64::prelude::*;
use serde_json::Value as Json;
use ssi_claims::jwt::VerifiablePresentation;

#[derive(Debug, Clone)]
pub struct IdToken(pub String);

impl TypedParameter for IdToken {
    const KEY: &'static str = "id_token";
}

impl TryFrom<Json> for IdToken {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map(Self).map_err(Into::into)
    }
}

impl From<IdToken> for Json {
    fn from(value: IdToken) -> Self {
        value.0.into()
    }
}

#[derive(Debug, Clone)]
pub struct VpToken(pub String);

impl TypedParameter for VpToken {
    const KEY: &'static str = "vp_token";
}

impl TryFrom<Json> for VpToken {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map(Self).map_err(Into::into)
    }
}

impl From<VpToken> for Json {
    fn from(value: VpToken) -> Self {
        value.0.into()
    }
}

impl VpToken {
    /// Parse the VP Token as a JSON object.
    ///
    /// This will attempt to decode the token as base64, and if that fails, it
    /// will attempt to parse the token as a JSON object.
    ///
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.2
    ///
    /// If you want to check for decode errors, use [VpToken::decode_base64].
    pub fn parse(&self) -> Result<Json, Error> {
        match self.decode_base64() {
            Ok(decoded) => Ok(decoded),
            Err(_) => Ok(serde_json::from_str(&self.0)?),
        }
    }

    /// Return the Verifiable Presentation Token as a JSON object from a base64
    /// encoded string.
    pub fn decode_base64(&self) -> Result<Json, Error> {
        let decoded = BASE64_STANDARD.decode(&self.0)?;
        Ok(serde_json::from_slice(&decoded)?)
    }

    /// Validate the Verifiable Presentation Token.
    pub fn validate(
        &self,
        presentation_definition: &PresentationDefinition,
        descriptor_map: &[DescriptorMap],
    ) -> Result<(), Error> {
        let vp_payload = self.parse()?;

        // Check if the vp_payload is an array of VPs
        match vp_payload.as_array() {
            None => {
                // handle a single verifiable presentation
                presentation_definition.validate_presentation(
                    VerifiablePresentation(json_syntax::Value::from(vp_payload)),
                    descriptor_map,
                )?;
            }
            Some(vps) => {
                // Each item in the array is a VP
                for vp in vps {
                    // handle the verifiable presentation
                    presentation_definition.validate_presentation(
                        VerifiablePresentation(json_syntax::Value::from(vp.clone())),
                        descriptor_map,
                    )?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PresentationSubmission {
    raw: Json,
    parsed: PresentationSubmissionParsed,
}

impl PresentationSubmission {
    pub fn into_parsed(self) -> PresentationSubmissionParsed {
        self.parsed
    }

    pub fn parsed(&self) -> &PresentationSubmissionParsed {
        &self.parsed
    }
}

impl TryFrom<PresentationSubmissionParsed> for PresentationSubmission {
    type Error = Error;

    fn try_from(parsed: PresentationSubmissionParsed) -> Result<Self, Self::Error> {
        let raw = serde_json::to_value(parsed.clone())?;
        Ok(Self { raw, parsed })
    }
}

impl TypedParameter for PresentationSubmission {
    const KEY: &'static str = "presentation_submission";
}

impl TryFrom<Json> for PresentationSubmission {
    type Error = Error;

    fn try_from(raw: Json) -> Result<Self, Self::Error> {
        let parsed = serde_json::from_value(raw.clone())?;
        Ok(Self { raw, parsed })
    }
}

impl From<PresentationSubmission> for Json {
    fn from(value: PresentationSubmission) -> Self {
        value.raw
    }
}
