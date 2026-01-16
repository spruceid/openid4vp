use super::object::UntypedObject;

use anyhow::{Context, Error, Result};
use parameters::State;
use serde::{Deserialize, Serialize};
use url::Url;

use self::parameters::VpToken;

pub mod parameters;

/// Authorization Response.
///
/// The response can be either:
/// - `Unencoded`: Plain response with `vp_token` and optional `state`
/// - `Jwt`: Encrypted response as JWE (for `direct_post.jwt` response mode)
///
/// See [OID4VP Section 6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthorizationResponse {
    Unencoded(UnencodedAuthorizationResponse),
    Jwt(JwtAuthorizationResponse),
}

impl AuthorizationResponse {
    /// Parse an Authorization Response from `application/x-www-form-urlencoded` bytes.
    ///
    /// This handles both:
    /// - JWT/JWE responses (for `direct_post.jwt` mode)
    /// - Unencoded responses (for `direct_post` mode)
    pub fn from_x_www_form_urlencoded(bytes: &[u8]) -> Result<Self> {
        // Try JWT response first (for direct_post.jwt mode)
        if let Ok(jwt) = serde_urlencoded::from_bytes(bytes) {
            return Ok(Self::Jwt(jwt));
        }

        // Parse as unencoded response
        let unencoded = serde_urlencoded::from_bytes::<JsonEncodedAuthorizationResponse>(bytes)
            .context("failed to parse authorization response")?;

        let vp_token: VpToken =
            serde_json::from_str(&unencoded.vp_token).context("failed to decode vp_token")?;

        let state: Option<State> = unencoded.state.map(State).or(None);

        Ok(Self::Unencoded(UnencodedAuthorizationResponse {
            vp_token,
            state,
        }))
    }
}

/// Internal struct for form-urlencoded parsing/serialization.
#[derive(Debug, Deserialize, Serialize)]
struct JsonEncodedAuthorizationResponse {
    /// `vp_token` is JSON string encoded.
    pub(crate) vp_token: String,
    /// `state` is a regular string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<String>,
}

/// Unencoded Authorization Response.
///
/// Used with `direct_post` response mode (unencrypted).
///
/// > The Authorization Response MUST contain the `vp_token` parameter.
/// > The `state` parameter MUST be included if it was present in the Authorization Request.
///
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnencodedAuthorizationResponse {
    /// The VP Token containing credential presentations.
    ///
    /// This is a JSON object mapping credential query IDs
    /// (from `dcql_query`) to arrays of Verifiable Presentations.
    pub vp_token: VpToken,

    /// Optional state value echoed from the Authorization Request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
}

impl UnencodedAuthorizationResponse {
    /// Create a new Authorization Response with a VP Token.
    pub fn new(vp_token: VpToken) -> Self {
        Self {
            vp_token,
            state: None,
        }
    }

    /// Create a new Authorization Response with a VP Token and state.
    pub fn with_state(vp_token: VpToken, state: State) -> Self {
        Self {
            vp_token,
            state: Some(state),
        }
    }

    /// Encode the Authorization Response as `application/x-www-form-urlencoded`.
    pub fn into_x_www_form_urlencoded(self) -> Result<String> {
        let encoded = serde_urlencoded::to_string(JsonEncodedAuthorizationResponse::from(self))
            .context("failed to encode authorization response as x-www-form-urlencoded")?;

        Ok(encoded)
    }

    /// Return the Verifiable Presentation Token.
    pub fn vp_token(&self) -> &VpToken {
        &self.vp_token
    }

    /// Return the state value, if present.
    pub fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }
}

impl From<UnencodedAuthorizationResponse> for JsonEncodedAuthorizationResponse {
    fn from(value: UnencodedAuthorizationResponse) -> Self {
        let vp_token = serde_json::to_string(&value.vp_token)
            // SAFETY: VP Token will always be a valid JSON object.
            .unwrap();

        let state = value.state.map(|s| s.0);

        Self { vp_token, state }
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
    use crate::core::response::parameters::{VpToken, VpTokenItem};

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
        // vp_token is an object mapping credential IDs to presentations
        let vp_token = VpToken::with_credential(
            "my_credential",
            vec![VpTokenItem::String(
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...".into(),
            )],
        );

        let response = UnencodedAuthorizationResponse::new(vp_token);
        let url_encoded = response.into_x_www_form_urlencoded().unwrap();

        // Should contain vp_token as JSON object
        assert!(url_encoded.contains("vp_token="));
        assert!(url_encoded.contains("my_credential"));
    }

    #[test]
    fn unencoded_authorization_response_with_state() {
        use crate::core::authorization_request::parameters::State;

        let vp_token = VpToken::with_credential(
            "credential_query_1",
            vec![VpTokenItem::String(
                "sd-jwt-vc~disclosure1~disclosure2~kb-jwt".into(),
            )],
        );

        let response = UnencodedAuthorizationResponse::with_state(vp_token, State("abc123".into()));

        let url_encoded = response.into_x_www_form_urlencoded().unwrap();

        assert!(url_encoded.contains("vp_token="));
        assert!(url_encoded.contains("state=abc123"));
    }

    #[test]
    fn vp_token_dcql_format() {
        // Test that VpToken serializes to the DCQL format
        let mut vp_token = VpToken::new();
        vp_token.insert("cred1", vec![VpTokenItem::String("jwt1".into())]);
        vp_token.insert(
            "cred2",
            vec![
                VpTokenItem::String("jwt2a".into()),
                VpTokenItem::String("jwt2b".into()),
            ],
        );

        let json = serde_json::to_value(&vp_token).unwrap();

        // Should be an object with credential IDs as keys
        assert!(json.is_object());
        assert!(json.get("cred1").is_some());
        assert!(json.get("cred2").is_some());

        // cred1 should have 1 presentation
        let cred1 = json.get("cred1").unwrap().as_array().unwrap();
        assert_eq!(cred1.len(), 1);

        // cred2 should have 2 presentations
        let cred2 = json.get("cred2").unwrap().as_array().unwrap();
        assert_eq!(cred2.len(), 2);
    }
}
