//! OID4VP library data structures that are needed on the frontend, without all of the other
//! dependencies that can cause compilation issues with web targets.
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Status of an OID4VP session.
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
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

/// Outcome of an OID4VP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Outcome {
    /// An error occurred during response processing.
    Error { cause: String },
    /// The authorization response did not pass verification.
    Failure { reason: String },
    /// The authorization response is verified.
    Success { info: Json },
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
            Outcome::Success { .. } => 2,
        }
    }
}

impl PartialOrd for Outcome {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.ordering().partial_cmp(&other.ordering())
    }
}
