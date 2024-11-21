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
    pub fn supports_security_method(
        &self,
        format: &ClaimFormatDesignation,
        security_method: &String,
    ) -> bool {
        match self.0.get(format) {
            Some(ClaimFormatPayload::Alg(alg_values))
            | Some(ClaimFormatPayload::AlgValuesSupported(alg_values)) => {
                alg_values.contains(security_method)
            }
            Some(ClaimFormatPayload::ProofType(proof_types)) => {
                proof_types.contains(security_method)
            }
            _ => false,
        }
    }
}

impl TypedParameter for VpFormats {
    const KEY: &'static str = "vp_formats";
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

#[derive(Debug, Clone)]
pub struct RequireSignedRequestObject(pub bool);

impl TypedParameter for RequireSignedRequestObject {
    const KEY: &'static str = "require_signed_request_object";
}

impl TryFrom<Json> for RequireSignedRequestObject {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<RequireSignedRequestObject> for Json {
    fn from(value: RequireSignedRequestObject) -> Json {
        Json::Bool(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEncryptedResponseAlg(pub String);

impl TypedParameter for AuthorizationEncryptedResponseAlg {
    const KEY: &'static str = "authorization_encrypted_response_alg";
}

impl TryFrom<Json> for AuthorizationEncryptedResponseAlg {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEncryptedResponseAlg> for Json {
    fn from(value: AuthorizationEncryptedResponseAlg) -> Json {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEncryptedResponseEnc(pub String);

impl TypedParameter for AuthorizationEncryptedResponseEnc {
    const KEY: &'static str = "authorization_encrypted_response_enc";
}

impl TryFrom<Json> for AuthorizationEncryptedResponseEnc {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEncryptedResponseEnc> for Json {
    fn from(value: AuthorizationEncryptedResponseEnc) -> Json {
        Json::String(value.0)
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
                     "kid":"1"
                  }
               ]
            },
            "authorization_encrypted_response_alg":"ECDH-ES",
            "authorization_encrypted_response_enc":"A256GCM",
            "require_signed_request_object":true,
            "vp_formats":{ "mso_mdoc":{} }
        }
        ))
        .unwrap()
    }

    #[test]
    fn vp_formats() {
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
        assert_eq!(jwk.get("kid").unwrap(), "1");
    }

    #[test]
    fn require_signed_request_object() {
        let exp = true;
        let RequireSignedRequestObject(b) = metadata().get().unwrap().unwrap();
        assert_eq!(b, exp);
    }

    #[test]
    fn authorization_encrypted_response_alg() {
        let exp = "ECDH-ES";
        let AuthorizationEncryptedResponseAlg(s) = metadata().get().unwrap().unwrap();
        assert_eq!(s, exp);
    }

    #[test]
    fn authorization_encrypted_response_enc() {
        let exp = "A256GCM";
        let AuthorizationEncryptedResponseEnc(s) = metadata().get().unwrap().unwrap();
        assert_eq!(s, exp);
    }
}
