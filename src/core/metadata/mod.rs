use std::ops::{Deref, DerefMut};

use anyhow::Error;
use serde::{Deserialize, Serialize};

use self::parameters::wallet::{
    AuthorizationEndpoint, ClientIdSchemesSupported, VpFormatsSupported,
};

use super::object::{ParsingErrorContext, UntypedObject};

pub mod parameters;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct WalletMetadata(
    UntypedObject,
    AuthorizationEndpoint,
    VpFormatsSupported,
    ClientIdSchemesSupported,
);

impl WalletMetadata {
    pub fn new(
        authorization_endpoint: AuthorizationEndpoint,
        vp_formats_supported: VpFormatsSupported,
        client_id_schemes_supported: Option<ClientIdSchemesSupported>,
        other: Option<UntypedObject>,
    ) -> Self {
        Self(
            other.unwrap_or_default(),
            authorization_endpoint,
            vp_formats_supported,
            client_id_schemes_supported.unwrap_or_default(),
        )
    }

    pub fn authorization_endpoint(&self) -> &AuthorizationEndpoint {
        &self.1
    }

    pub fn vp_formats_supported(&self) -> &VpFormatsSupported {
        &self.2
    }

    pub fn client_id_schemes_supported(&self) -> &ClientIdSchemesSupported {
        &self.3
    }
}

impl From<WalletMetadata> for UntypedObject {
    fn from(value: WalletMetadata) -> Self {
        let mut inner = value.0;
        inner.insert(value.1);
        inner.insert(value.2);
        inner.insert(value.3);
        inner
    }
}

impl TryFrom<UntypedObject> for WalletMetadata {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        let authorization_endpoint = value.get().parsing_error()?;
        let vp_formats_supported = value.get().parsing_error()?;
        let client_id_schemes_supported = value.get_or_default().parsing_error()?;
        Ok(Self(
            value,
            authorization_endpoint,
            vp_formats_supported,
            client_id_schemes_supported,
        ))
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
