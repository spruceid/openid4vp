use serde::{Deserialize, Serialize};
use url::Url;

use self::builder::SessionBuilder;

use crate::core::{
    authorization_request::AuthorizationRequestObject, metadata::WalletMetadata, profile::Verifier,
};

pub mod builder;
pub mod request_signer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session<P: Verifier> {
    profile: P,
    authorization_request: Url,
    request_object: AuthorizationRequestObject,
    request_object_jwt: String,
}

impl<P: Verifier> Session<P> {
    pub fn builder(profile: P, wallet_metadata: WalletMetadata) -> SessionBuilder<P> {
        SessionBuilder::new(profile, wallet_metadata)
    }

    pub fn authorization_request(&self) -> &Url {
        &self.authorization_request
    }

    pub fn request_object_jwt(&self) -> &str {
        &self.request_object_jwt
    }
}
