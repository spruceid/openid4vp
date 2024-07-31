use anyhow::Error;
use serde_json::Value as Json;

pub use crate::core::authorization_request::parameters::State;
use crate::core::object::TypedParameter;

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

#[derive(Debug, Clone)]
pub struct PresentationSubmission {
    raw: Json,
    parsed: crate::presentation_exchange::PresentationSubmission,
}

impl PresentationSubmission {
    pub fn into_parsed(self) -> crate::presentation_exchange::PresentationSubmission {
        self.parsed
    }

    pub fn parsed(&self) -> &crate::presentation_exchange::PresentationSubmission {
        &self.parsed
    }
}

impl TryFrom<crate::presentation_exchange::PresentationSubmission> for PresentationSubmission {
    type Error = Error;

    fn try_from(
        parsed: crate::presentation_exchange::PresentationSubmission,
    ) -> Result<Self, Self::Error> {
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
