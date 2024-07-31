use std::ops::{Deref, DerefMut};

use anyhow::Error;
use parameters::wallet::{RequestObjectSigningAlgValuesSupported, ResponseTypesSupported};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use self::parameters::wallet::{AuthorizationEndpoint, VpFormatsSupported};

use super::{
    authorization_request::parameters::ResponseType,
    object::{ParsingErrorContext, UntypedObject},
};

pub mod parameters;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct WalletMetadata(UntypedObject, AuthorizationEndpoint, VpFormatsSupported);

impl WalletMetadata {
    pub fn new(
        authorization_endpoint: AuthorizationEndpoint,
        vp_formats_supported: VpFormatsSupported,
        other: Option<UntypedObject>,
    ) -> Self {
        Self(
            other.unwrap_or_default(),
            authorization_endpoint,
            vp_formats_supported,
        )
    }

    pub fn authorization_endpoint(&self) -> &AuthorizationEndpoint {
        &self.1
    }

    pub fn vp_formats_supported(&self) -> &VpFormatsSupported {
        &self.2
    }

    /// The static wallet metadata bound to `openid4vp:`:
    /// ```json
    /// {
    ///   "authorization_endpoint": "openid4vp:",
    ///   "response_types_supported": [
    ///     "vp_token"
    ///   ],
    ///   "vp_formats_supported": {
    ///     "jwt_vp_json": {
    ///       "alg_values_supported": ["ES256"]
    ///     },
    ///     "jwt_vc_json": {
    ///       "alg_values_supported": ["ES256"]
    ///     }
    ///   },
    ///   "request_object_signing_alg_values_supported": [
    ///     "ES256"
    ///   ]
    /// }
    /// ```
    pub fn openid4vp_scheme_static() -> Self {
        // Unwrap safety: unit tested.
        let authorization_endpoint = AuthorizationEndpoint("openid4vp:".parse().unwrap());

        let response_types_supported = ResponseTypesSupported(vec![ResponseType::VpToken]);

        let mut format_definition = Map::new();
        format_definition.insert(
            "alg_values_supported".to_owned(),
            Json::Array(vec![Json::String("ES256".to_owned())]),
        );
        let format_definition = Json::Object(format_definition);
        let mut vp_formats_supported = Map::new();
        vp_formats_supported.insert("jwt_vp_json".to_owned(), format_definition.clone());
        vp_formats_supported.insert("jwt_vc_json".to_owned(), format_definition.clone());
        let vp_formats_supported = VpFormatsSupported(vp_formats_supported);

        let request_object_signing_alg_values_supported =
            RequestObjectSigningAlgValuesSupported(vec!["ES256".to_owned()]);

        let mut object = UntypedObject::default();

        object.insert(authorization_endpoint);
        object.insert(response_types_supported);
        object.insert(vp_formats_supported);
        object.insert(request_object_signing_alg_values_supported);

        // Unwrap safety: unit tested.
        object.try_into().unwrap()
    }
}

impl From<WalletMetadata> for UntypedObject {
    fn from(value: WalletMetadata) -> Self {
        let mut inner = value.0;
        inner.insert(value.1);
        inner.insert(value.2);
        inner
    }
}

impl TryFrom<UntypedObject> for WalletMetadata {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        let authorization_endpoint = value.get().parsing_error()?;
        let vp_formats_supported = value.get().parsing_error()?;
        Ok(Self(value, authorization_endpoint, vp_formats_supported))
    }
}

impl Deref for WalletMetadata {
    type Target = UntypedObject;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WalletMetadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use super::WalletMetadata;

    #[test]
    fn openid4vp_scheme_static() {
        let expected = serde_json::json!(
          {
            "authorization_endpoint": "openid4vp:",
            "response_types_supported": [
              "vp_token"
            ],
            "vp_formats_supported": {
              "jwt_vp_json": {
                "alg_values_supported": ["ES256"]
              },
              "jwt_vc_json": {
                "alg_values_supported": ["ES256"]
              }
            },
            "request_object_signing_alg_values_supported": [
              "ES256"
            ]
          }
        );

        let wallet_metadata = WalletMetadata::openid4vp_scheme_static();

        assert_eq!(expected, serde_json::to_value(wallet_metadata).unwrap())
    }
}
