use std::collections::HashMap;
use thiserror::Error;

/// Result of credential selection from the wallet engine
#[derive(Debug, Clone)]
pub struct CredentialSelection {
    /// Mapping: credential_query_id -> Vec<raw_credential>
    ///
    /// Each entry corresponds to a credential query in the DCQL request.
    /// The value is a list of raw credential strings (JWT, SD-JWT, etc.)
    pub presentations: HashMap<String, Vec<String>>,
}

impl CredentialSelection {
    /// Create an empty credential selection
    pub fn new() -> Self {
        Self {
            presentations: HashMap::new(),
        }
    }

    /// Add a credential for a query ID
    pub fn add(&mut self, query_id: &str, credential: String) {
        self.presentations
            .entry(query_id.to_string())
            .or_default()
            .push(credential);
    }

    /// Check if the selection is empty
    pub fn is_empty(&self) -> bool {
        self.presentations.is_empty()
    }
}

impl Default for CredentialSelection {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur in the wallet engine
#[derive(Debug, Error)]
pub enum EngineError {
    /// No credential matches the query
    #[error("No matching credential for query: {0}")]
    NoMatchingCredential(String),

    /// User declined the presentation request
    #[error("User declined the request")]
    UserDeclined,

    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Missing required parameter
    #[error("Missing parameter: {0}")]
    MissingParameter(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for EngineError {
    fn from(err: anyhow::Error) -> Self {
        EngineError::Internal(err.to_string())
    }
}
