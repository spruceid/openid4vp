//! Wallet Engine abstraction
//!
//! The `WalletEngine` trait defines the interface for credential selection and
//! presentation. Two implementations are planned:
//!
//! - `HeadlessEngine`: Automatic responses with mock credentials
//! - `MobileEngine`: Bridge to real mobile wallet via HTTP/WebSocket/gRPC (future)

mod headless;
mod types;

pub use headless::{HeadlessConfig, HeadlessEngine};
pub use types::*;

use async_trait::async_trait;
use openid4vp::core::authorization_request::AuthorizationRequestObject;
use openid4vp::core::response::parameters::VpToken;

/// Wallet Engine abstraction
///
/// This trait defines the interface for processing OID4VP authorization requests
/// and building responses. Implementations can be:
///
/// - `HeadlessEngine`: Automatic responses with mock credentials
/// - `MobileEngine`: Delegate to real mobile wallet
#[async_trait]
pub trait WalletEngine: Send + Sync {
    /// Process an authorization request and select matching credentials
    ///
    /// For `HeadlessEngine`: Automatic selection based on DCQL query
    /// For `MobileEngine`: Send request to mobile app and wait for user consent
    async fn process_request(
        &self,
        request: &AuthorizationRequestObject,
    ) -> Result<CredentialSelection, EngineError>;

    /// Build the vp_token for the selected credentials
    ///
    /// Creates Verifiable Presentations wrapping the selected credentials,
    /// signed with the holder's key and including the nonce for replay protection.
    async fn build_vp_token(
        &self,
        selection: &CredentialSelection,
        nonce: &str,
        audience: &str,
    ) -> Result<VpToken, EngineError>;

    /// Get the wallet's public keys (for JWKS endpoint)
    fn public_keys(&self) -> Vec<serde_json::Value>;

    /// Get the number of credentials in the store
    fn credentials_count(&self) -> usize;
}
