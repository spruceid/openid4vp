use std::ops::{Deref, DerefMut};

use anyhow::{bail, Error, Result};
use parameters::wallet::{RequestObjectSigningAlgValuesSupported, ResponseTypesSupported};
use serde::{Deserialize, Serialize};
use ssi_jwk::Algorithm;

use crate::presentation_exchange::{ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload};

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

    /// Return a reference to the vp formats supported.
    pub fn vp_formats_supported(&self) -> &VpFormatsSupported {
        &self.2
    }

    /// Return a mutable reference to the vp formats supported.
    pub fn vp_formats_supported_mut(&mut self) -> &mut VpFormatsSupported {
        &mut self.2
    }

    // /// Returns whether the claim format is supported.
    // pub fn is_claim_format_supported(&self, designation: &ClaimFormatDesignation) -> bool {
    //     self.vp_formats_supported()
    //         .is_claim_format_supported(designation)
    // }

    /// Adds a new algorithm to the list of supported request object signing algorithms.
    pub fn add_request_object_signing_alg(&mut self, alg: String) -> Result<()> {
        self.0
            .get::<RequestObjectSigningAlgValuesSupported>()
            .transpose()?
            .map(|x| x.0)
            .get_or_insert_with(Vec::new)
            .push(alg);

        Ok(())
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

        let alg_values_supported = vec![Algorithm::ES256.to_string()];

        let mut vp_formats_supported = ClaimFormatMap::new();
        vp_formats_supported.insert(
            ClaimFormatDesignation::JwtVpJson,
            ClaimFormatPayload::AlgValuesSupported(alg_values_supported.clone()),
        );
        vp_formats_supported.insert(
            ClaimFormatDesignation::JwtVcJson,
            ClaimFormatPayload::AlgValuesSupported(alg_values_supported.clone()),
        );
        let vp_formats_supported = VpFormatsSupported(vp_formats_supported);

        let request_object_signing_alg_values_supported =
            RequestObjectSigningAlgValuesSupported(alg_values_supported);

        let mut object = UntypedObject::default();

        object.insert(authorization_endpoint);
        object.insert(response_types_supported);
        object.insert(vp_formats_supported);
        object.insert(request_object_signing_alg_values_supported);

        // Unwrap safety: unit tested.
        object.try_into().unwrap()
    }

    /// Return the `request_object_signing_alg_values_supported`
    /// field from the wallet metadata.
    pub fn request_object_signing_alg_values_supported(&self) -> Result<Vec<String>, Error> {
        let Some(Ok(algs)) = self.get::<RequestObjectSigningAlgValuesSupported>() else {
            bail!(
                "Failed to parse request object signing algorithms supported from wallet metadata."
            )
        };

        Ok(algs.0)
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
