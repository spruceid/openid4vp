use crate::core::{
    authorization_request::parameters::{ClientIdScheme, ResponseType},
    credential_format::{ClaimFormatDesignation, ClaimFormatMap},
    object::TypedParameter,
};

use anyhow::{bail, Error, Result};
use serde_json::Value as Json;
use url::Url;

#[derive(Debug, Clone)]
pub struct Issuer(pub String);

impl TypedParameter for Issuer {
    const KEY: &'static str = "issuer";
}

impl TryFrom<Json> for Issuer {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<Issuer> for Json {
    fn from(value: Issuer) -> Json {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEndpoint(pub Url);

impl TypedParameter for AuthorizationEndpoint {
    const KEY: &'static str = "authorization_endpoint";
}

impl TryFrom<Json> for AuthorizationEndpoint {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEndpoint> for Json {
    fn from(value: AuthorizationEndpoint) -> Json {
        Json::String(value.0.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ResponseTypesSupported(pub Vec<ResponseType>);

impl TypedParameter for ResponseTypesSupported {
    const KEY: &'static str = "response_types_supported";
}

impl TryFrom<Json> for ResponseTypesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<ResponseTypesSupported> for Json {
    fn from(value: ResponseTypesSupported) -> Json {
        Json::Array(
            value
                .0
                .iter()
                .cloned()
                .map(String::from)
                .map(Json::from)
                .collect(),
        )
    }
}

// TODO: Client ID scheme types?
#[derive(Debug, Clone)]
pub struct ClientIdSchemesSupported(pub Vec<ClientIdScheme>);

impl TypedParameter for ClientIdSchemesSupported {
    const KEY: &'static str = "client_id_schemes_supported";
}

impl TryFrom<Json> for ClientIdSchemesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let Json::Array(xs) = value else {
            bail!("expected JSON array")
        };
        xs.into_iter()
            .map(Json::try_into)
            .collect::<Result<Vec<ClientIdScheme>>>()
            .map(Self)
    }
}

impl From<ClientIdSchemesSupported> for Json {
    fn from(value: ClientIdSchemesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

impl Default for ClientIdSchemesSupported {
    fn default() -> Self {
        Self(vec![ClientIdScheme(
            ClientIdScheme::PREREGISTERED.to_string(),
        )])
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestObjectSigningAlgValuesSupported(pub Vec<String>);

impl TypedParameter for RequestObjectSigningAlgValuesSupported {
    const KEY: &'static str = "request_object_signing_alg_values_supported";
}

impl TryFrom<Json> for RequestObjectSigningAlgValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<RequestObjectSigningAlgValuesSupported> for Json {
    fn from(value: RequestObjectSigningAlgValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone, Default)]
pub struct VpFormatsSupported(pub ClaimFormatMap);

impl TypedParameter for VpFormatsSupported {
    const KEY: &'static str = "vp_formats_supported";
}

impl TryFrom<Json> for VpFormatsSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map(Self).map_err(Into::into)
    }
}

impl TryFrom<VpFormatsSupported> for Json {
    type Error = Error;

    fn try_from(value: VpFormatsSupported) -> Result<Json, Self::Error> {
        serde_json::to_value(value.0).map_err(Into::into)
    }
}

impl VpFormatsSupported {
    pub fn is_claim_format_supported(&self, designation: &ClaimFormatDesignation) -> bool {
        self.0.contains_key(designation)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEncryptionAlgValuesSupported(pub Vec<String>);

impl TypedParameter for AuthorizationEncryptionAlgValuesSupported {
    const KEY: &'static str = "authorization_encryption_alg_values_supported";
}

impl TryFrom<Json> for AuthorizationEncryptionAlgValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEncryptionAlgValuesSupported> for Json {
    fn from(value: AuthorizationEncryptionAlgValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEncryptionEncValuesSupported(pub Vec<String>);

impl TypedParameter for AuthorizationEncryptionEncValuesSupported {
    const KEY: &'static str = "authorization_encryption_enc_values_supported";
}

impl TryFrom<Json> for AuthorizationEncryptionEncValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEncryptionEncValuesSupported> for Json {
    fn from(value: AuthorizationEncryptionEncValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
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
        serde_json::from_value(json!({
            "issuer": "https://self-issued.me/v2",
            "authorization_endpoint": "mdoc-openid4vp://",
            "response_types_supported": [
                "vp_token"
            ],
            "vp_formats_supported":
            {
                "mso_mdoc": {
                }
            },
            "client_id_schemes_supported": [
                "redirect_uri",
                "x509_san_uri"
            ],
            "request_object_signing_alg_values_supported": [
              "ES256"
            ],
            "authorization_encryption_alg_values_supported": [
              "ECDH-ES"
            ],
            "authorization_encryption_enc_values_supported": [
              "A256GCM"
            ]
        }
        ))
        .unwrap()
    }

    #[test]
    fn issuer() {
        let exp = "https://self-issued.me/v2";
        let Issuer(s) = metadata().get().unwrap().unwrap();
        assert_eq!(s, exp);
    }

    #[test]
    fn authorization_endpoint() {
        let exp = "mdoc-openid4vp://".parse().unwrap();
        let AuthorizationEndpoint(s) = metadata().get().unwrap().unwrap();
        assert_eq!(s, exp);
    }

    #[test]
    fn response_types_supported() {
        let exp = [ResponseType::VpToken];
        let ResponseTypesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    fn client_id_schemes_supported() {
        let exp = [
            ClientIdScheme(ClientIdScheme::REDIRECT_URI.to_string()),
            ClientIdScheme(ClientIdScheme::X509_SAN_DNS.to_string()),
        ];
        let ClientIdSchemesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    fn request_object_signing_alg_values_supported() {
        let exp = ["ES256".to_string()];
        let RequestObjectSigningAlgValuesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    fn vp_formats_supported() {
        let VpFormatsSupported(mut m) = metadata().get().unwrap().unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(
            m.remove(&ClaimFormatDesignation::MsoMDoc).unwrap(),
            ClaimFormatPayload::Other(serde_json::Value::Object(Default::default()))
        );
    }

    #[test]
    fn authorization_encryption_alg_values_supported() {
        let exp = ["ECDH-ES".to_string()];
        let AuthorizationEncryptionAlgValuesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    fn authorization_encryption_enc_values_supported() {
        let exp = ["A256GCM".to_string()];
        let AuthorizationEncryptionEncValuesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }
}
