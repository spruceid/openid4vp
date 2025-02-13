use super::{object::UntypedObject, presentation_submission::PresentationSubmission};

use anyhow::{Context, Error, Result};
use parameters::State;
use serde::{Deserialize, Serialize};
use url::Url;

use self::parameters::VpToken;

pub mod parameters;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthorizationResponse {
    Unencoded(UnencodedAuthorizationResponse),
    Jwt(JwtAuthorizationResponse),
}

impl AuthorizationResponse {
    pub fn from_x_www_form_urlencoded(bytes: &[u8]) -> Result<Self> {
        if let Ok(jwt) = serde_urlencoded::from_bytes(bytes) {
            return Ok(Self::Jwt(jwt));
        }

        let unencoded = serde_urlencoded::from_bytes::<JsonEncodedAuthorizationResponse>(bytes)
            .context("failed to construct flat map")?;

        let vp_token: VpToken =
            serde_json::from_str(&unencoded.vp_token).context("failed to decode vp token")?;

        let presentation_submission: PresentationSubmission =
            serde_json::from_str(&unencoded.presentation_submission)
                .context("failed to decode presentation submission")?;

        let state: Option<State> = unencoded
            .state
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .context("failed to decode state")?;

        Ok(Self::Unencoded(UnencodedAuthorizationResponse {
            vp_token,
            presentation_submission,
            state,
        }))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct JsonEncodedAuthorizationResponse {
    /// `presentation_submission` is JSON string encoded.
    pub(crate) presentation_submission: String,
    /// `vp_token` is JSON string encoded.
    pub(crate) vp_token: String,
    /// `state` is a regular string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnencodedAuthorizationResponse {
    pub presentation_submission: PresentationSubmission,
    pub vp_token: VpToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
}

impl UnencodedAuthorizationResponse {
    /// Encode the Authorization Response as 'application/x-www-form-urlencoded'.
    pub fn into_x_www_form_urlencoded(self) -> Result<String> {
        let encoded = serde_urlencoded::to_string(JsonEncodedAuthorizationResponse::from(self))
            .context(
                "failed to encode presentation_submission as 'application/x-www-form-urlencoded'",
            )?;

        Ok(encoded)
    }

    /// Return the Verifiable Presentation Token.
    pub fn vp_token(&self) -> &VpToken {
        &self.vp_token
    }

    /// Return the Presentation Submission.
    pub fn presentation_submission(&self) -> &PresentationSubmission {
        &self.presentation_submission
    }
}

// Helper method for cleaning up quoted strings.
// urlencoding a JSON string adds quotes around the string,
// which causes issues when decoding.
fn clean_quoted_string(s: &str) -> String {
    s.trim_matches(|c| c == '"' || c == '\'').to_string()
}

impl From<UnencodedAuthorizationResponse> for JsonEncodedAuthorizationResponse {
    fn from(value: UnencodedAuthorizationResponse) -> Self {
        let vp_token = serde_json::to_string(&value.vp_token)
            .ok()
            // Need to strip quotes from the string.
            .map(|s| clean_quoted_string(&s))
            // SAFTEY: VP Token will always be a valid JSON object.
            .unwrap();

        let presentation_submission = serde_json::to_string(&value.presentation_submission)
            // SAFETY: presentation submission will always be a valid JSON object.
            .unwrap();

        let state = value
            .state
            .map(|s| serde_json::to_string(&s))
            .transpose()
            // SAFETY: State will always be a valid JSON object.
            .unwrap();

        Self {
            vp_token,
            presentation_submission,
            state,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuthorizationResponse {
    /// Can be JWT or JWE.
    pub response: String,
}

impl JwtAuthorizationResponse {
    /// Encode the Authorization Response as 'application/x-www-form-urlencoded'.
    pub fn into_x_www_form_urlencoded(self) -> Result<String> {
        serde_urlencoded::to_string(self)
            .context("failed to encode response as 'application/x-www-form-urlencoded'")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostRedirection {
    pub redirect_uri: Url,
}

impl TryFrom<UntypedObject> for UnencodedAuthorizationResponse {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(serde_json::Value::Object(value.0))?)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::core::object::UntypedObject;

    use super::{JwtAuthorizationResponse, UnencodedAuthorizationResponse};

    #[test]
    fn jwt_authorization_response_to_form_urlencoded() {
        let response = JwtAuthorizationResponse {
            response: "header.body.signature".into(),
        };
        assert_eq!(
            response.into_x_www_form_urlencoded().unwrap(),
            "response=header.body.signature",
        )
    }

    #[test]
    fn unencoded_authorization_response_to_form_urlencoded() {
        let object: UntypedObject = serde_json::from_value(json!(
            {
                "presentation_submission": {
                    "id": "d05a7f51-ac09-43af-8864-e00f0175f2c7",
                    "definition_id": "f619e64a-8f80-4b71-8373-30cf07b1e4f2",
                    "descriptor_map": []
                },
                "vp_token": "string"
            }
        ))
        .unwrap();
        let response = UnencodedAuthorizationResponse::try_from(object).unwrap();
        let url_encoded = response.into_x_www_form_urlencoded().unwrap();

        assert!(url_encoded.contains("presentation_submission=%7B%22id%22%3A%22d05a7f51-ac09-43af-8864-e00f0175f2c7%22%2C%22definition_id%22%3A%22f619e64a-8f80-4b71-8373-30cf07b1e4f2%22%2C%22descriptor_map%22%3A%5B%5D%7D"));
        assert!(url_encoded.contains("vp_token=string"));
    }
}
