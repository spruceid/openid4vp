use crate::core::metadata::ClaimFormatPayload;
use crate::core::object::TypedParameter;
use crate::core::{credential_format::ClaimFormatMap, metadata::ClaimFormatDesignation};

use anyhow::{Context, Error};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpFormats(pub ClaimFormatMap);

impl VpFormats {
    /// Returns a boolean to denote whether a particular pair of format and security method
    /// are supported in the VP formats. A security method could be a JOSE algorithm, a COSE
    /// algorithm, a Cryptosuite, etc.
    ///
    /// NOTE: This method is interested in the security method of the claim format
    /// payload and not the claim format designation.
    ///
    /// For example, the security method would need to match one of the `alg`
    /// values in the claim format payload.
    ///
    /// - For jwt_vc_json/jwt_vp_json: matches against `alg_values` (Section B.1.3.1.3)
    /// - For ldp_vc/ldp_vp: matches against `proof_type_values` (Section B.1.3.2.3)
    pub fn supports_security_method(
        &self,
        format: &ClaimFormatDesignation,
        security_method: &String,
    ) -> bool {
        match self.0.get(format) {
            Some(ClaimFormatPayload::AlgValues(alg_values)) => alg_values.contains(security_method),
            Some(ClaimFormatPayload::ProofTypeValues(proof_types)) => {
                proof_types.contains(security_method)
            }
            _ => false,
        }
    }
}

impl TypedParameter for VpFormats {
    const KEY: &'static str = "vp_formats_supported";
}

impl TryFrom<Json> for VpFormats {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map(Self).map_err(Into::into)
    }
}

impl TryFrom<VpFormats> for Json {
    type Error = Error;

    fn try_from(value: VpFormats) -> Result<Json, Self::Error> {
        serde_json::to_value(value.0).context("Failed to serialize VpFormats")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JWKs {
    pub keys: Vec<Map<String, Json>>,
}

impl TypedParameter for JWKs {
    const KEY: &'static str = "jwks";
}

impl TryFrom<Json> for JWKs {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(Into::into)
    }
}

impl From<JWKs> for Json {
    fn from(value: JWKs) -> Json {
        let keys = value.keys.into_iter().map(Json::Object).collect();
        let mut obj = Map::default();
        obj.insert("keys".into(), Json::Array(keys));
        obj.into()
    }
}

/// Encrypted response enc values supported by the verifier.
///
/// Per OID4VP v1.0 Section 5.1, this is an array of JWE `enc` algorithms.
/// Default is `A128GCM` if not specified.
#[derive(Debug, Clone)]
pub struct EncryptedResponseEncValuesSupported(pub Vec<String>);

impl TypedParameter for EncryptedResponseEncValuesSupported {
    const KEY: &'static str = "encrypted_response_enc_values_supported";
}

impl TryFrom<Json> for EncryptedResponseEncValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<EncryptedResponseEncValuesSupported> for Json {
    fn from(value: EncryptedResponseEncValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::String).collect())
    }
}

impl Default for EncryptedResponseEncValuesSupported {
    fn default() -> Self {
        // Default to A128GCM per OID4VP v1.0 Section 8.3
        Self(vec!["A128GCM".to_string()])
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::core::{
        credential_format::{ClaimFormatDesignation, ClaimFormatPayload},
        object::UntypedObject,
    };

    use super::*;

    fn metadata() -> UntypedObject {
        // OID4VP v1.0 compliant client_metadata example
        // Per Section 5.1 and 8.3:
        // - jwks contains keys with `alg` parameter (required for encryption)
        // - encrypted_response_enc_values_supported specifies enc algorithms
        serde_json::from_value(json!(
        {
            "jwks":{
               "keys":[
                  {
                     "kty":"EC",
                     "crv":"P-256",
                     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                     "use":"enc",
                     "alg":"ECDH-ES",
                     "kid":"1"
                  }
               ]
            },
            "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
            "vp_formats_supported":{ "mso_mdoc":{} }
        }
        ))
        .unwrap()
    }

    #[test]
    fn vp_formats_supported() {
        let VpFormats(formats) = metadata().get().unwrap().unwrap();

        let mso_doc = formats
            .get(&ClaimFormatDesignation::MsoMDoc)
            .expect("failed to find mso doc");

        assert_eq!(
            mso_doc,
            &ClaimFormatPayload::Other(serde_json::Value::Object(Default::default()))
        )
    }

    #[test]
    fn jwks() {
        let JWKs { keys } = metadata().get().unwrap().unwrap();
        assert_eq!(keys.len(), 1);

        let jwk = &keys[0];
        assert_eq!(jwk.get("kty").unwrap(), "EC");
        assert_eq!(jwk.get("crv").unwrap(), "P-256");
        assert_eq!(
            jwk.get("x").unwrap(),
            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
        );
        assert_eq!(
            jwk.get("y").unwrap(),
            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        );
        assert_eq!(jwk.get("use").unwrap(), "enc");
        assert_eq!(jwk.get("alg").unwrap(), "ECDH-ES");
        assert_eq!(jwk.get("kid").unwrap(), "1");
    }

    #[test]
    fn encrypted_response_enc_values_supported() {
        let EncryptedResponseEncValuesSupported(encs) = metadata().get().unwrap().unwrap();
        assert_eq!(encs, vec!["A128GCM", "A256GCM"]);
    }

    #[test]
    fn encrypted_response_enc_values_supported_default() {
        let default = EncryptedResponseEncValuesSupported::default();
        assert_eq!(default.0, vec!["A128GCM"]);
    }
}
