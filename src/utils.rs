use anyhow;
use josekit::JoseError;
use reqwest::Error as ReqwestError;
use serde::{Deserialize, Serialize};
use serde_cbor::Error as CborError;
use ssi::jws::Error as JwsError;
use std::ops::Deref;

// #[derive(Clone)]
// pub struct JsonPath(JsonPathInst);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "Vec<T>", into = "Vec<T>")]
pub struct NonEmptyVec<T: Clone>(Vec<T>);

#[derive(Debug, thiserror::Error)]
pub enum Openid4vpError {
    #[error(
        "The request is missing a required parameter, includes an
    invalid parameter value, includes a parameter more than
    once, or is otherwise malformed."
    )]
    InvalidRequest,
    #[error(
        "The client is not authorized to request an authorization
    code using this method"
    )]
    UnauthorizedClient,
    #[error(
        "The resource owner or authorization server denied the
    request."
    )]
    AccessDenied,
    #[error(
        "The authorization server does not support obtaining an
    authorization code using this method."
    )]
    UnnsupportedResponseType,
    #[error("Requested scope value is invalid, unknown, or malformed.")]
    InvalidScope,
    #[error(
        "The server encountered an unexpected
    condition that prevented it from fulfilling the request."
    )]
    ServerError,
    #[error(
        "The server is currently unable to handle
    the request due to a temporary overloading or maintenance
    of the server."
    )]
    TemporarilyUnavailable,
    #[error("Verifier's pre-registered metadata has been found based on the Client Identifier, but client_metadata parameter is also present.")]
    InvalidClient,
    #[error("The Wallet does not support any of the formats requested by the Verifier")]
    VpFormatsNotSupported,
    #[error("The Presentation Definition URL cannot be reached.")]
    InvalidPresentationDefinitionUri,
    #[error("The Presentation Definition URL can be reached, but the specified presentation_definition cannot be found at the URL.")]
    InvalidPresentationDefinitionReference,
    #[error("{0}")]
    Empty(String),
    #[error("Field requested that cannot be mapped to an ISO18013-5 mDL field")]
    UnrecognizedField,
    #[error("Could not encode or decode cbor")]
    CborError,
    #[error("Could not instantiate session manager")]
    OID4VPError,
    #[error("Isomdl error {0}")]
    IsomdlError(String),
    #[error("The requested encryption algorithm is not supported.")]
    UnsupportedEncryptionAlgorithm,
    #[error("The requested encryption encoding is not supported.")]
    UnsupportedEncryptionEncoding,
    #[error("There is an error in the base64 encoding.")]
    DecodingError,
    #[error("JoseError {0}")]
    JoseError(String),
    #[error("ResponseError {0}")]
    ResponseError(String),
}

impl<T: Clone> NonEmptyVec<T> {
    pub fn new(t: T) -> Self {
        Self(vec![t])
    }

    pub fn maybe_new(v: Vec<T>) -> Option<Self> {
        Self::try_from(v).ok()
    }

    pub fn push(&mut self, t: T) {
        self.0.push(t)
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: Clone> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Openid4vpError;

    fn try_from(v: Vec<T>) -> Result<NonEmptyVec<T>, Openid4vpError> {
        if v.is_empty() {
            return Err(Openid4vpError::Empty(
                "Can not create a NonEmptyVec from an empty Vec".to_string(),
            ));
        }
        Ok(NonEmptyVec(v))
    }
}

impl<T: Clone> From<NonEmptyVec<T>> for Vec<T> {
    fn from(NonEmptyVec(v): NonEmptyVec<T>) -> Vec<T> {
        v
    }
}

impl<T: Clone> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Clone> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl From<JwsError> for Openid4vpError {
    fn from(_value: JwsError) -> Self {
        Openid4vpError::UnrecognizedField
    }
}

impl From<CborError> for Openid4vpError {
    fn from(_value: CborError) -> Self {
        Openid4vpError::CborError
    }
}

impl From<anyhow::Error> for Openid4vpError {
    fn from(value: anyhow::Error) -> Self {
        Openid4vpError::Empty(value.to_string())
    }
}

impl From<JoseError> for Openid4vpError {
    fn from(value: JoseError) -> Self {
        Openid4vpError::JoseError(value.to_string())
    }
}

impl From<ReqwestError> for Openid4vpError {
    fn from(_value: reqwest::Error) -> Self {
        Openid4vpError::InvalidRequest
    }
}

impl From<serde_json::Error> for Openid4vpError {
    fn from(value: serde_json::Error) -> Self {
        Openid4vpError::Empty(value.to_string())
    }
}

impl From<x509_cert::der::Error> for Openid4vpError {
    fn from(_value: x509_cert::der::Error) -> Self {
        Openid4vpError::InvalidRequest
    }
}

impl From<ssi::jwk::Error> for Openid4vpError {
    fn from(_value: ssi::jwk::Error) -> Self {
        Openid4vpError::InvalidRequest
    }
}

impl From<base64::DecodeError> for Openid4vpError {
    fn from(_value: base64::DecodeError) -> Self {
        Openid4vpError::DecodingError
    }
}

impl From<String> for Openid4vpError {
    fn from(_value: String) -> Self {
        Openid4vpError::OID4VPError
    }
}

impl From<p256::ecdsa::Error> for Openid4vpError {
    fn from(value: p256::ecdsa::Error) -> Self {
        Openid4vpError::JoseError(value.to_string())
    }
}

impl From<x509_cert::spki::Error> for Openid4vpError {
    fn from(value: x509_cert::spki::Error) -> Self {
        Openid4vpError::ResponseError(value.to_string())
    }
}
