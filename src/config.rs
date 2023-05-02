use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub base: BaseUrl,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Http {
    pub port: u16,
    pub address: [u8; 4],
}

/// A url that is always a base (can be safely join()'ed with further path elements without
/// mangling).
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct BaseUrl(Url);

impl std::ops::Deref for BaseUrl {
    type Target = Url;

    fn deref(&self) -> &Url {
        &self.0
    }
}

impl TryFrom<String> for BaseUrl {
    type Error = url::ParseError;

    fn try_from(mut url: String) -> Result<Self, Self::Error> {
        // Make URL a base.
        if !url.ends_with('/') {
            url += "/"
        }
        url.parse().map(Self)
    }
}
