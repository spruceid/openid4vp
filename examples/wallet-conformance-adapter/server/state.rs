use crate::config::Config;
use crate::engine::WalletEngine;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    /// The wallet engine (HeadlessEngine or MobileEngine)
    pub engine: Arc<dyn WalletEngine>,
    /// Configuration
    pub config: Config,
}

impl AppState {
    /// Create a new application state
    pub fn new(engine: Arc<dyn WalletEngine>, config: Config) -> Self {
        Self { engine, config }
    }
}
