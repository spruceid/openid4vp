//! Headless Wallet Engine implementation
//!
//! Provides automatic responses with mock credentials for conformance testing.

use super::{CredentialSelection, EngineError, WalletEngine};
use crate::credentials::CredentialStore;
use crate::crypto::{create_key_binding_jwt, public_jwk};
use crate::dcql::DcqlMatcher;
use async_trait::async_trait;
use openid4vp::core::authorization_request::AuthorizationRequestObject;
use openid4vp::core::dcql_query::DcqlQuery;
use openid4vp::core::response::parameters::{VpToken, VpTokenItem};
use tracing::{debug, info, warn};

/// Configuration for the headless engine
#[derive(Debug, Clone)]
pub struct HeadlessConfig {
    /// If true, automatically consent to all valid requests
    pub auto_consent: bool,
    /// Artificial delay in milliseconds (to simulate real wallet latency)
    pub response_delay_ms: u64,
}

impl Default for HeadlessConfig {
    fn default() -> Self {
        Self {
            auto_consent: true,
            response_delay_ms: 0,
        }
    }
}

/// Headless Wallet Engine
///
/// Automatically responds to OID4VP authorization requests using mock credentials.
pub struct HeadlessEngine {
    credentials: CredentialStore,
    config: HeadlessConfig,
}

impl HeadlessEngine {
    pub fn new(config: HeadlessConfig) -> Self {
        Self {
            credentials: CredentialStore::with_mock_credentials(),
            config,
        }
    }
}

#[async_trait]
impl WalletEngine for HeadlessEngine {
    async fn process_request(
        &self,
        request: &AuthorizationRequestObject,
    ) -> Result<CredentialSelection, EngineError> {
        info!("Processing authorization request (headless mode)");

        if self.config.response_delay_ms > 0 {
            debug!(
                delay_ms = self.config.response_delay_ms,
                "Adding artificial delay"
            );
            tokio::time::sleep(std::time::Duration::from_millis(
                self.config.response_delay_ms,
            ))
            .await;
        }

        if !self.config.auto_consent {
            warn!("Auto-consent disabled, declining request");
            return Err(EngineError::UserDeclined);
        }

        let dcql_query: DcqlQuery = request
            .dcql_query()
            .ok_or_else(|| EngineError::MissingParameter("dcql_query is required".to_string()))?
            .map_err(|e| EngineError::Internal(format!("Failed to parse DCQL: {}", e)))?;

        debug!(?dcql_query, "Extracted DCQL query");

        let matcher = DcqlMatcher::new(&self.credentials);
        let selection = matcher.match_query(&dcql_query)?;

        info!(
            matched_count = selection.presentations.len(),
            "Successfully matched credentials"
        );

        Ok(selection)
    }

    async fn build_vp_token(
        &self,
        selection: &CredentialSelection,
        nonce: &str,
        audience: &str,
    ) -> Result<VpToken, EngineError> {
        debug!(
            nonce,
            audience,
            credentials = selection.presentations.len(),
            "Building vp_token"
        );

        let mut vp_token = VpToken::new();

        for (cred_id, credentials) in &selection.presentations {
            let mut presentations = Vec::new();

            for credential in credentials {
                // SD-JWT: replace the placeholder KB-JWT with a fresh one
                let parts: Vec<&str> = credential.split('~').collect();
                if parts.len() >= 2 {
                    // Build the SD-JWT without the old KB-JWT
                    let sd_jwt_without_kb = format!("{}~", parts[..parts.len() - 1].join("~"));

                    // Create fresh key binding JWT
                    let kb_jwt = create_key_binding_jwt(&sd_jwt_without_kb, nonce, audience)
                        .map_err(|e| EngineError::CryptoError(e.to_string()))?;

                    let sd_jwt_with_kb = format!("{}{}", sd_jwt_without_kb, kb_jwt);
                    presentations.push(VpTokenItem::String(sd_jwt_with_kb));
                } else {
                    presentations.push(VpTokenItem::String(credential.clone()));
                }
            }

            vp_token.insert(cred_id.clone(), presentations);
        }

        info!(
            token_entries = vp_token.len(),
            "Successfully built vp_token"
        );
        Ok(vp_token)
    }

    fn public_keys(&self) -> Vec<serde_json::Value> {
        vec![public_jwk()]
    }

    fn credentials_count(&self) -> usize {
        self.credentials.count()
    }
}
