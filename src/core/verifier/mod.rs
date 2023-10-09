use serde::{Deserialize, Serialize};
use url::Url;

use self::builder::SessionBuilder;

use super::{authorization_request::AuthorizationRequestObject, metadata::WalletMetadata};

pub mod builder;
pub mod request_signer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    authorization_request: Url,
    request_object: AuthorizationRequestObject,
    request_object_jwt: String,
}

impl Session {
    pub fn builder(wallet_metadata: WalletMetadata) -> SessionBuilder {
        SessionBuilder::new(wallet_metadata)
    }

    pub fn authorization_request(&self) -> &Url {
        &self.authorization_request
    }

    pub fn request_object_jwt(&self) -> &str {
        &self.request_object_jwt
    }
}
