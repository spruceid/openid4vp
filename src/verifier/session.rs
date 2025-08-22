use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

use anyhow::{bail, Ok, Result};
use async_trait::async_trait;
pub use openid4vp_frontend::*;
#[cfg(feature = "test")]
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::core::{
    authorization_request::AuthorizationRequestObject, dcql_query::DcqlQuery,
    presentation_definition::PresentationDefinition,
};

#[derive(Debug, Clone)]
pub struct Session {
    pub uuid: Uuid,
    pub status: Status,
    pub authorization_request_jwt: String,
    pub authorization_request_object: AuthorizationRequestObject,
    pub presentation_definition: Option<PresentationDefinition>,
    pub dcql_query: Option<DcqlQuery>,
}

/// Storage interface for session information.
#[async_trait]
pub trait SessionStore: Debug {
    /// Store a new authorization request session.
    async fn initiate(&self, session: Session) -> Result<()>;

    /// Update the status of a session.
    async fn update_status(&self, uuid: Uuid, status: Status) -> Result<()>;

    /// Get a session from the store.
    async fn get_session(&self, uuid: Uuid) -> Result<Session>;

    /// Remove a session from the store.
    async fn remove_session(&self, uuid: Uuid) -> Result<()>;
}

/// A local in-memory store. Not for production use!
///
/// # Warning
/// This in-memory store should only be used for test purposes, it will not work for a distributed
/// deployment.
#[cfg(feature = "test")]
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    store: Arc<Mutex<BTreeMap<Uuid, Session>>>,
}

#[cfg(feature = "test")]
#[async_trait]
impl SessionStore for MemoryStore {
    async fn initiate(&self, session: Session) -> Result<()> {
        self.store.try_lock()?.insert(session.uuid, session);

        Ok(())
    }

    async fn update_status(&self, uuid: Uuid, status: Status) -> Result<()> {
        if let Some(session) = self.store.try_lock()?.get_mut(&uuid) {
            session.status = status;
            return Ok(());
        }
        bail!("session not found")
    }

    async fn get_session(&self, uuid: Uuid) -> Result<Session> {
        if let Some(session) = self.store.try_lock()?.get(&uuid) {
            return Ok(session.clone());
        }

        bail!("session not found")
    }

    async fn remove_session(&self, uuid: Uuid) -> Result<()> {
        if self.store.try_lock()?.remove(&uuid).is_some() {
            return Ok(());
        }

        bail!("session not found")
    }
}
