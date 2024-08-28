use super::{
    object::{ParsingErrorContext, UntypedObject},
    presentation_definition::PresentationDefinition,
    presentation_submission::DescriptorMap,
};

use std::collections::{BTreeMap, HashMap};

use anyhow::{bail, Context, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::jwt::VerifiablePresentation;
use url::Url;

use self::parameters::{PresentationSubmission, VpToken};

pub mod parameters;

#[derive(Debug, Clone)]
pub enum AuthorizationResponse {
    Unencoded(UnencodedAuthorizationResponse),
    Jwt(JwtAuthorizationResponse),
}

impl AuthorizationResponse {
    pub fn from_x_www_form_urlencoded(bytes: &[u8]) -> Result<Self> {
        if let Ok(jwt) = serde_urlencoded::from_bytes(bytes) {
            return Ok(Self::Jwt(jwt));
        }

        let flattened = serde_urlencoded::from_bytes::<BTreeMap<String, String>>(bytes)
            .context("failed to construct flat map")?;
        let map = flattened
            .into_iter()
            .map(|(k, v)| {
                let v = serde_json::from_str::<Value>(&v).unwrap_or(Value::String(v));
                (k, v)
            })
            .collect();

        Ok(Self::Unencoded(UntypedObject(map).try_into()?))
    }

    /// Validate an authorization response against a presentation definition.
    ///
    /// This method will parse the presentation submission from the auth response and
    /// validate it against the provided presentation definition.
    ///
    /// # Parameters
    ///
    /// - `self` - The authorization response to validate.
    /// - `presentation_definition` - The presentation definition to validate against.
    ///
    /// # Errors
    ///
    /// This method will return an error if the presentation submission does not match the
    /// presentation definition.
    ///
    /// # Returns
    ///
    /// This method will return `Ok(())` if the presentation submission matches the presentation
    /// definition.
    pub fn validate(&self, presentation_definition: &PresentationDefinition) -> Result<()> {
        match self {
            AuthorizationResponse::Jwt(_jwt) => {
                // TODO: Handle JWT Encoded authorization response.

                bail!("Authorization Response Presentation Definition validation not implemented.")
            }
            AuthorizationResponse::Unencoded(response) => {
                let presentation_submission = response.presentation_submission().parsed();

                // Ensure the definition id matches the submission's definition id.
                if presentation_submission.definition_id() != presentation_definition.id() {
                    bail!("Presentation Definition ID does not match the Presentation Submission.")
                }

                // Parse the descriptor map into a HashMap for easier access
                let descriptor_map: HashMap<String, DescriptorMap> = presentation_submission
                    .descriptor_map()
                    .iter()
                    .map(|descriptor_map| (descriptor_map.id().to_owned(), descriptor_map.clone()))
                    .collect();

                // Parse the VP Token according to the Spec, here:
                // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.2
                let vp_payload = response.vp_token().parse()?;

                // Check if the vp_payload is an array of VPs
                match vp_payload.as_array() {
                    None => {
                        // handle a single verifiable presentation
                        presentation_definition.validate_definition_map(
                            VerifiablePresentation(json_syntax::Value::from(vp_payload)),
                            &descriptor_map,
                        )
                    }
                    Some(vps) => {
                        // Each item in the array is a VP
                        for vp in vps {
                            // handle the verifiable presentation
                            presentation_definition.validate_definition_map(
                                VerifiablePresentation(json_syntax::Value::from(vp.clone())),
                                &descriptor_map,
                            )?;
                        }

                        Ok(())
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnencodedAuthorizationResponse(
    pub UntypedObject,
    pub VpToken,
    pub PresentationSubmission,
);

impl UnencodedAuthorizationResponse {
    /// Encode the Authorization Response as 'application/x-www-form-urlencoded'.
    pub fn into_x_www_form_urlencoded(self) -> Result<String> {
        let mut inner = self.0;
        inner.insert(self.1);
        inner.insert(self.2);
        serde_urlencoded::to_string(inner.flatten_for_form()?)
            .context("failed to encode response as 'application/x-www-form-urlencoded'")
    }

    /// Return the Verifiable Presentation Token.
    pub fn vp_token(&self) -> &VpToken {
        &self.1
    }

    /// Return the Presentation Submission.
    pub fn presentation_submission(&self) -> &PresentationSubmission {
        &self.2
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
        let vp_token = value.get().parsing_error()?;
        let presentation_submission = value.get().parsing_error()?;
        Ok(Self(value, vp_token, presentation_submission))
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
        assert_eq!(
            response.into_x_www_form_urlencoded().unwrap(),
            "presentation_submission=%7B%22id%22%3A%22d05a7f51-ac09-43af-8864-e00f0175f2c7%22%2C%22definition_id%22%3A%22f619e64a-8f80-4b71-8373-30cf07b1e4f2%22%2C%22descriptor_map%22%3A%5B%5D%7D&vp_token=string",
        )
    }
}
