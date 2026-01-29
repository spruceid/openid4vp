use url::Url;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    /// The authorization endpoint URL (public-facing)
    pub authorization_endpoint: Url,

    /// Public URL of the adapter (used for metadata)
    pub public_url: Url,

    /// Port to listen on
    pub port: u16,

    /// Host to bind to
    pub host: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            authorization_endpoint: "http://localhost:3000/authorize".parse().unwrap(),
            public_url: "http://localhost:3000".parse().unwrap(),
            port: 3000,
            host: "0.0.0.0".to_string(),
        }
    }
}
