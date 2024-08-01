use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

use anyhow::{bail, Error, Ok, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    core::authorization_request::AuthorizationRequestObject,
    presentation_exchange::PresentationDefinition,
};

#[derive(Debug, Clone)]
pub struct Session {
    pub uuid: Uuid,
    pub status: Status,
    pub authorization_request_jwt: String,
    pub authorization_request_object: AuthorizationRequestObject,
    pub presentation_definition: PresentationDefinition,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum Status {
    /// Wallet has been sent the request by reference, waiting for the wallet to request the request.
    SentRequestByReference,
    /// Wallet has received the request, waiting on the wallet to process the request.
    SentRequest,
    /// Verifier has received the response and is now processing it.
    ReceivedResponse,
    /// Verifier has finished processing the response.
    Complete(Outcome),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// An error occurred during response processing.
    Error { cause: Arc<Error> },
    /// The authorization response did not pass verification.
    Failure { reason: String },
    /// The authorization response is verified.
    Success,
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
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    store: Arc<Mutex<BTreeMap<Uuid, Session>>>,
}

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

impl PartialEq for Outcome {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl Outcome {
    fn ordering(&self) -> u8 {
        match self {
            Outcome::Error { .. } => 0,
            Outcome::Failure { .. } => 1,
            Outcome::Success => 2,
        }
    }
}

impl PartialOrd for Outcome {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.ordering().partial_cmp(&other.ordering())
    }
}
